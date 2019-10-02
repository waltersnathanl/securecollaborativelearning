//package club.securecollaborativelearning;

import paillierp.PaillierThreshold;
import paillierp.PartialDecryption;
import paillierp.key.KeyGen;
import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.zkp.DecryptionZKP;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Random;

public class AggregatorCloud{
    //In practice these functions ended up being less useful than anticipated.
    public static Object send(InetAddress target, int port, Object message) throws IOException, ClassNotFoundException {
        Socket socket = new Socket(target, port);
        OutputStream outputStream = socket.getOutputStream();
        InputStream inputStream = socket.getInputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        objectOutputStream.writeObject(message);
        Object payload = objectInputStream.readObject();
        socket.close();
        return payload;
    }

    public static Object get(int port, Object returnMessage) throws IOException, ClassNotFoundException {
        ServerSocket serverSocket = new ServerSocket(port);
        Socket socket = serverSocket.accept();
        OutputStream outputStream = socket.getOutputStream();
        InputStream inputStream = socket.getInputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        ObjectInputStream objectInputStream = new ObjectInputStream((inputStream));
        objectOutputStream.writeObject(returnMessage);
        Object payload = objectInputStream.readObject();
        socket.close();
        return payload;
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //Task 1: get a list we can use to communicate with all the clients.
        InetAddress[] clients = new InetAddress [5];
        clients[0] = InetAddress.getByName("172.31.21.68");
        clients[1] = InetAddress.getByName("172.31.18.11");
        clients[2] = InetAddress.getByName("172.31.18.51");
        clients[3] = InetAddress.getByName("172.31.28.118");
        clients[4] = InetAddress.getByName("172.31.17.216");

        InetAddress keyMaster = InetAddress.getByName("172.31.22.38");
        int number_of_clients = clients.length;
        int port = 8080;

        //Let's also initialize RSA
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048,new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE,publicKey);

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE,privateKey);

        Object junk;
        //send aggregator's address to all clients and get their public keys
        PublicKey[] publicKeys = new PublicKey[number_of_clients+1];

        for(int i=0;i<number_of_clients;i++) {
            publicKeys[i] = (PublicKey) send(clients[i], port, InetAddress.getLocalHost());
            System.out.println("Public key received from client " + i);
        }
        publicKeys[number_of_clients] = publicKey;

        //Now let's have an extended conversation with the KeyMaster
        Socket socket = new Socket(keyMaster, port);
        OutputStream outputStream = socket.getOutputStream();
        InputStream inputStream = socket.getInputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        objectOutputStream.writeObject(InetAddress.getLocalHost());
        objectOutputStream.writeObject(number_of_clients+1);
        for(int i = 0; i < publicKeys.length; i++){
            objectOutputStream.writeObject(publicKeys[i]);
            System.out.println("Public Key " + i + " transmitted");
        }

        byte[][] encryptedPaillierKeys = new byte[publicKeys.length][];
        for(int i = 0; i < publicKeys.length; i++){
            encryptedPaillierKeys[i] = (byte[]) objectInputStream.readObject();
            System.out.println("Encrypted Paillier key " + i + " received");
        }
        socket.close();

        //We now have all the keys.  Let's send them out and decrypt our own
        for(int i=0;i<number_of_clients;i++){
            junk = send(clients[i],port,encryptedPaillierKeys[i]);
            System.out.println("Paillier key delivered to client " + i);
        }
        byte[] decryptedBytestream = decryptCipher.doFinal(encryptedPaillierKeys[publicKeys.length-1]);
        PaillierPrivateThresholdKey paillierKey = new PaillierPrivateThresholdKey(decryptedBytestream,1L);
        //This seed is irrelevant after key creation but the constructor wants it anyway so we just give it a fixed value
        PaillierThreshold thresholdKey = new PaillierThreshold(paillierKey);

        System.out.println("all keys distributed");

        //Task 2: distribute the query and acquire coded responses
        //subtask 1: create the query.  This includes the value names and the values of epsilon for differential privacy
        String query = "qSELECT cancer_events, cancer_total, normal_events, normal_total FROM healthdata;&&&cancer_events:0.25&&&cancer_total:0.25&&&normal_events:0.25&&&normal_total:0.25";
        int length_of_response = 4;

        //subtask 2: collect encrypted responses
        BigInteger[][] responseMatrix = new BigInteger[number_of_clients][];
        BigInteger[] arrayResponse;
        for(int i=0;i<number_of_clients;i++){
            socket = new Socket(clients[i],port);
            outputStream = socket.getOutputStream();
            inputStream = socket.getInputStream();
            objectOutputStream = new ObjectOutputStream(outputStream);
            objectInputStream = new ObjectInputStream(inputStream);
            objectOutputStream.writeObject(query);
            arrayResponse = (BigInteger[]) objectInputStream.readObject();
            responseMatrix[i] = arrayResponse;
            String finished = (String) objectInputStream.readObject();
            objectOutputStream.close();
            objectInputStream.close();
            socket.close();
            System.out.println("Queried client " + i);
        }

        //Task 3: add up the responses
        BigInteger[] aggregatedResponses = new BigInteger[length_of_response];
        BigInteger current_value;
        for(int j=0;j<length_of_response;j++){
            current_value = responseMatrix[0][j];
            for(int i=1;i<number_of_clients;i++){
                current_value = thresholdKey.add(current_value,responseMatrix[i][j]);
            }
            aggregatedResponses[j] = current_value;
        }
        System.out.println("Responses aggregated");

        //Task 4: distribute the aggregates and decipher
        BigInteger[] cleartextAggregates = new BigInteger[length_of_response];
        PartialDecryption currentPartialDecryption;
        for(int j=0;j<length_of_response;j++){
            PartialDecryption[] partialDecryptions = new PartialDecryption[number_of_clients];
            for(int i=0;i<clients.length;i++) {
                socket = new Socket(clients[i],port);
                outputStream = socket.getOutputStream();
                inputStream = socket.getInputStream();
                objectOutputStream = new ObjectOutputStream(outputStream);
                objectInputStream = new ObjectInputStream(inputStream);
                //System.out.println("Sending partial decryption " + j + " to client " + i);
                objectOutputStream.writeObject("e" + aggregatedResponses[j].toString(10));
                currentPartialDecryption = (PartialDecryption) objectInputStream.readObject();
                partialDecryptions[i] = currentPartialDecryption;
                socket.close();
            }
            cleartextAggregates[j] = thresholdKey.combineShares(partialDecryptions);
            System.out.println("Decrypted output value " + j);
        }
        //Task 5: Final processing.
        //order is cancer_events, cancer_total, normal_events, normal_total
        double numerator = ((cleartextAggregates[0].intValue()))*(cleartextAggregates[3].intValue());
        double denominator =(cleartextAggregates[1].intValue() * cleartextAggregates[2].intValue());
        double oddsRatio = numerator/denominator;
        System.out.println("The odds ratio is " + oddsRatio);
        /*
        //This patch of code is specifically for gathering data for benchmarking purposes and should be turned off usually
        File outputfile = new File("/home/nwalters/epsilon25.txt");
        BufferedWriter writer = new BufferedWriter(new FileWriter(outputfile,true));
        writer.write(oddsRatio + "/n");

        writer.close();
        */


        //Success!  Now let's tell all our clients to stand down.
        for(int i=0;i<number_of_clients;i++){
            socket = new Socket(clients[i],port);
            outputStream = socket.getOutputStream();
            objectOutputStream = new ObjectOutputStream(outputStream);
            objectOutputStream.writeObject("k");
        }
    }
}


