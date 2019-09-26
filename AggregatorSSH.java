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

public class AggregatorSSH{

    public static Object send(InetAddress target, int port, Object message) throws IOException, ClassNotFoundException {
        Socket socket = new Socket(target, 8080);
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
        ServerSocket serverSocket = new ServerSocket(8080);
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
        InetAddress[] clients = new InetAddress [3];
        clients[0] = InetAddress.getByName("54.202.197.122");
        clients[1] = InetAddress.getByName("34.223.215.79");
        clients[2] = InetAddress.getLocalHost();  //The KeyMaster wants to know this
        InetAddress keyMaster = InetAddress.getByName(""); //TODO populate this

        int number_of_clients = clients.length-1;
        int port = 8080;

        //Let's also initialize RSA
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024,new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE,publicKey);

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE,privateKey);

        Object junk;
        //send aggregator's address to all clients
        for(int i=0;i<number_of_clients;i++){
            junk = send(clients[i],port,clients[number_of_clients]);
        }

        //send client list to KeyMaster
        System.out.println("Requesting Keys...");
        junk = send(keyMaster,port,clients);
        //wait for a public key request
        junk = get(port,publicKey);
        //wait for an encrypted Paillier Key
        byte[] bytestream = (byte[]) get(port,"confirmed!");

        byte[] decryptedBytestream = decryptCipher.doFinal(bytestream);
        PaillierPrivateThresholdKey paillierKey = new PaillierPrivateThresholdKey(decryptedBytestream,1L);
        //This seed is irrelevant after key creation but the constructor wants it anyway.
        PaillierThreshold thresholdKey = new PaillierThreshold(paillierKey);

        //Task 2: distribute the query and acquire coded responses
        //subtask 1: create the query
        String query = "qSELECT cancer_events, cancer_total, normal_events, normal_total FROM healthdata;&&&cancer_events:1&&&cancer_total:1&&&normal_events:1&&&normal_total:1";
        int length_of_response = 4;

        //subtask 2: collect encrypted responses
        BigInteger[][] responseMatrix = new BigInteger[number_of_clients][];
        BigInteger[] arrayResponse;
        for(int i=0;i<number_of_clients;i++){
            junk = send(clients[i],8080,query);
            arrayResponse = (BigInteger[]) get(8080,"confirmed");
            responseMatrix[i] = arrayResponse;
        }

        //Task 3: aggregate the responses
        BigInteger[] aggregatedResponses = new BigInteger[length_of_response];
        BigInteger current_value;
        for(int j=0;j<length_of_response;j++){
            current_value = responseMatrix[0][j];
            for(int i=1;i<number_of_clients;i++){
                current_value = thresholdKey.add(current_value,responseMatrix[i][j]);
            }
            aggregatedResponses[j] = current_value;
        }

        //Task 4: distribute the aggregates and decipher
        BigInteger[] cleartextAggregates = new BigInteger[length_of_response];
        PartialDecryption currentPartialDecryption;
        for(int j=0;j<length_of_response;j++){
            PartialDecryption[] partialDecryptions = new PartialDecryption[number_of_clients];
            for(int i=0;i<clients.length;i++) {
                junk = send(clients[i], 8080, "e" + aggregatedResponses[j].toString(10));
                currentPartialDecryption = (PartialDecryption) get(port,"thanks;");
                partialDecryptions[i] = currentPartialDecryption;
            }
            cleartextAggregates[j] = thresholdKey.combineShares(partialDecryptions);
        }
        //Task 5: Final processing.
        //order is cancer_events, cancer_total, normal_events, normal_total
        double numerator = ((cleartextAggregates[0].intValue()))*(cleartextAggregates[3].intValue());
        double denominator =(cleartextAggregates[1].intValue() * cleartextAggregates[2].intValue());
        double oddsRatio = numerator/denominator;
        System.out.println("The odds ratio is " + oddsRatio);

        //Hooray!  Now let's tell all our clients to stand down.
        for(int i=0;i<number_of_clients;i++){
            junk = send(clients[i],port,"k");
        }
    }
}


