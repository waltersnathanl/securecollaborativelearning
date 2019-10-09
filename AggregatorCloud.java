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
import java.util.concurrent.TimeUnit;

public class AggregatorCloud{
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InterruptedException {
        //Task 1: get a list we can use to communicate with all the clients.
        InetAddress[] clients = new InetAddress [5];
        clients[0] = InetAddress.getByName("172.31.21.68");
        clients[1] = InetAddress.getByName("172.31.18.11");
        clients[2] = InetAddress.getByName("172.31.18.51");
        clients[3] = InetAddress.getByName("172.31.28.118");
        clients[4] = InetAddress.getByName("172.31.17.216");
        InetAddress keyMaster = InetAddress.getByName("172.31.22.38");
        //Service discovery would be awesome here.  As is, we hardcode the addresses
        int number_of_clients = clients.length;
        int port = 8080;

        //Let's also initialize RSA
        SecureRandom rnd = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048,new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();
        Cipher encryptCipher = Cipher.getInstance("RSA");
        Cipher decryptCipher = Cipher.getInstance("RSA");

        encryptCipher.init(Cipher.ENCRYPT_MODE,publicKey);
        decryptCipher.init(Cipher.DECRYPT_MODE,privateKey);

        Socket socket;
        OutputStream outputStream;
        InputStream inputStream;
        ObjectOutputStream objectOutputStream;
        ObjectInputStream objectInputStream;

        //get all the clients' public keys
        PublicKey[] publicKeys = new PublicKey[number_of_clients+1];
        for(int i=0;i<number_of_clients;i++) {
            socket = new Socket(clients[i],port);
            inputStream = socket.getInputStream();
            objectInputStream = new ObjectInputStream(inputStream);
            publicKeys[i] = (PublicKey) objectInputStream.readObject();
            System.out.println("Public key received from client " + i);
            socket.close();
        }
        publicKeys[number_of_clients] = publicKey;

        //Talk to the KeyMaster.  First we send public keys
        socket = new Socket(keyMaster, port);
        outputStream = socket.getOutputStream();
        inputStream = socket.getInputStream();
        objectOutputStream = new ObjectOutputStream(outputStream);
        objectInputStream = new ObjectInputStream(inputStream);
        objectOutputStream.writeObject(number_of_clients+1);
        for(int i = 0; i < publicKeys.length; i++){
            objectOutputStream.writeObject(publicKeys[i]);
            System.out.println("Public Key " + i + " transmitted");
        }

        //Now we receive encrypted Paillier keys
        byte[][] encryptedPaillierKeys = new byte[publicKeys.length][];
        for(int i = 0; i < publicKeys.length; i++){
            encryptedPaillierKeys[i] = (byte[]) objectInputStream.readObject();
            System.out.println("Encrypted Paillier key " + i + " received");
        }
        socket.close();

        //We now have all the keys.  Let's send them out, as well as salt values
        int currentSalt; //Would a Long be better?  No, because our cryptosystem can't handle large numbers...at least
                         //without doing a deep dive under the hood.
        int saltTotal = 0;
        for(int i=0;i<number_of_clients;i++){
            currentSalt = Math.abs(rnd.nextInt()); //Negative values are also a no-no for our crypto
            saltTotal += currentSalt;
            socket = new Socket(clients[i],port);
            outputStream = socket.getOutputStream();
            objectOutputStream = new ObjectOutputStream(outputStream);
            objectOutputStream.writeObject(encryptedPaillierKeys[i]);
            objectOutputStream.writeObject(currentSalt);
            System.out.println("Paillier key and salt delivered to client " + i);
        }
        BigInteger biSaltTotal = BigInteger.valueOf(saltTotal);
        byte[] decryptedBytestream = decryptCipher.doFinal(encryptedPaillierKeys[publicKeys.length-1]);
        PaillierPrivateThresholdKey paillierKey = new PaillierPrivateThresholdKey(decryptedBytestream,1L);
        //This seed is irrelevant after key creation but the constructor wants it anyway so we just give it a fixed value
        PaillierThreshold thresholdKey = new PaillierThreshold(paillierKey);
        System.out.println("all keys distributed");

        //distribute the query and acquire coded responses
        String query = "qSELECT cancer_events, cancer_total, normal_events, normal_total FROM healthdata;&&&cancer_events:0.25&&&cancer_total:0.25&&&normal_events:0.25&&&normal_total:0.25";
        //NB-initial character q means the rest of the string is a query, to be parsed as: query&&&key:value&&&key:value&&&...
        int length_of_response = 4;

        //collect encrypted responses
        BigInteger[][] responseMatrix = new BigInteger[number_of_clients][];
        BigInteger[] arrayResponse;

        for(int i=0;i<number_of_clients;i++){
            try{socket = new Socket(clients[i],port);}
            catch (Exception e){  //Occasionally the socket is not ready at this step.  It's rare but not rare enough.
                //This simple patch seems to cover it.
                System.out.println("ALERT! Exception raised connecting to client " + i +".  Trying again.");
                TimeUnit.SECONDS.sleep(1);
                socket = new Socket(clients[i],port);
            }
            outputStream = socket.getOutputStream();
            inputStream = socket.getInputStream();
            objectOutputStream = new ObjectOutputStream(outputStream);
            objectInputStream = new ObjectInputStream(inputStream);
            objectOutputStream.writeObject(query);
            arrayResponse = (BigInteger[]) objectInputStream.readObject();
            responseMatrix[i] = arrayResponse;
            objectOutputStream.close();
            objectInputStream.close();
            socket.close();
            System.out.println("Queried client " + i);
        }



        //add up the responses
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

        //distribute the aggregates and decipher
        BigInteger[] cleartextAggregates = new BigInteger[length_of_response];
        PartialDecryption currentPartialDecryption;

        for(int j=0;j<length_of_response;j++){
            PartialDecryption[] partialDecryptions = new PartialDecryption[number_of_clients+1];
            partialDecryptions[number_of_clients] = thresholdKey.decrypt(aggregatedResponses[j]);
            for(int i=0;i<number_of_clients;i++) {
                socket = new Socket(clients[i],port);
                outputStream = socket.getOutputStream();
                inputStream = socket.getInputStream();
                objectOutputStream = new ObjectOutputStream(outputStream);
                objectInputStream = new ObjectInputStream(inputStream);
                System.out.println("Sending partial decryption " + j + " to client " + i);
                objectOutputStream.writeObject("e" + aggregatedResponses[j].toString(10));
                currentPartialDecryption = (PartialDecryption) objectInputStream.readObject();
                partialDecryptions[i] = currentPartialDecryption;
                socket.close();
            }
            cleartextAggregates[j] = (thresholdKey.combineShares(partialDecryptions)).subtract(biSaltTotal);
            if(cleartextAggregates[j].compareTo(BigInteger.valueOf(0)) < 0){
                //This should happen only when epsilon is large, and even then it should be vanishingly rare.
                System.out.println("Too much noise added to the system!  Output would be nonsensical.");
                return;
            }
            System.out.println("Decrypted output value " + j);
        }
        //final processing.
        //order is cancer_events, cancer_total, normal_events, normal_total
        double numerator = ((cleartextAggregates[0].intValue()))*(cleartextAggregates[3].intValue());
        double denominator =(cleartextAggregates[1].intValue() * cleartextAggregates[2].intValue());
        double oddsRatio = numerator/denominator;
        System.out.println("The odds ratio is " + oddsRatio);


        /*
        //This patch of code was specifically for gathering data for benchmarking purposes and should usually be commented out
        File outputfile = new File("/home/nwalters/epsilon25.txt");
        BufferedWriter writer = new BufferedWriter(new FileWriter(outputfile,true));
        writer.write("0.25," + oddsRatio + "/n");

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