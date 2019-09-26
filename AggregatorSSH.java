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
        return objectInputStream.readObject();
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //Task 1: get a list we can use to communicate with all the clients.
        InetAddress[] clients = new InetAddress [3];
        clients[0] = InetAddress.getByName("54.202.197.122");
        clients[1] = InetAddress.getByName("34.223.215.79");
        InetAddress keyMaster = InetAddress.getByName(""); //TODO populate this

        int number_of_clients = clients.length;  //TODO If I don't have the KeyMaster read my IP, I need to put it in manually to clients and reduce this by one
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

        //send client list to KeyMaster
        System.out.println("Requesting Keys...");
        String reply = (String) send(keyMaster,port,clients);

        //wait for a public key request
        ServerSocket serverSocket = new ServerSocket(8080);
        Socket publicKeySocket = serverSocket.accept();
        OutputStream publicKeyOutputStream = publicKeySocket.getOutputStream();
        ObjectOutputStream publicKeyObjectOutputStream = new ObjectOutputStream(publicKeyOutputStream);
        publicKeyObjectOutputStream.writeObject(publicKey);
        publicKeySocket.close();

        //wait for an encrypted Paillier Key
        Socket paillierKeySocket = serverSocket.accept();
        OutputStream paillierKeyOutputStream = paillierKeySocket.getOutputStream();
        InputStream paillierKeyInputStream = paillierKeySocket.getInputStream();
        ObjectOutputStream paillierKeyObjectOutputStream = new ObjectOutputStream(paillierKeyOutputStream);
        ObjectInputStream paillierKeyObjectInputStream = new ObjectInputStream(paillierKeyInputStream);
        byte[] bytestream = (byte[]) paillierKeyObjectInputStream.readObject();
        byte[] decryptedBytestream = (byte[]) decryptCipher.doFinal(bytestream);
        PaillierPrivateThresholdKey paillierKey = new PaillierPrivateThresholdKey(decryptedBytestream,1L);
        paillierKeyObjectOutputStream.writeObject("Confirmed!");
        paillierKeySocket.close();
        serverSocket.close();

        PaillierThreshold thresholdKey = new PaillierThreshold(paillierKey);

/*        //Task 1: generate and distribute keys
        SecureRandom rnd = new SecureRandom();
        PaillierPrivateThresholdKey[] keys = KeyGen.PaillierThresholdKey(128,clients.length,clients.length,rnd.nextLong());
        //currently we have it set so everyone needs to work together to decrypt anything.
        PaillierThreshold myKey = new PaillierThreshold(keys[0]);
        //I'm totally stealing one of the private keys so I can do my own crypto.  Shhh!
        //PaillierPrivateThresholdKey[] privateKeys = new PaillierPrivateThresholdKey[clients.length];
        String currentResponse;
        byte[] currentMessage;
        for(int i=0;i<clients.length;i++){
            try (Socket socket = new Socket(clients[i],8080)){
                OutputStream outputStream = socket.getOutputStream();
                InputStream inputStream = socket.getInputStream();
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
                ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
                currentMessage = keys[i].toByteArray();
                objectOutputStream.writeObject(currentMessage);
                //System.out.println("boogers");
                while(objectInputStream.available()>0) {
                    System.out.println((String) objectInputStream.readObject());
                }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
        System.out.println("Keys Delivered!");
*/

        //Task 2: distribute the query and acquire coded responses
        //subtask 1: create the query
        String query = "qSELECT cancer_events, cancer_total, normal_events, normal_total FROM healthdata;&&&cancer_events:1&&&cancer_total:1&&&normal_events:1&&&normal_total:1";
        int length_of_response = 4;  //I'm not sure what we'll do if not hardcode every query.

        //subtask 2: collect encrypted responses
        BigInteger[][] responseMatrix = new BigInteger[number_of_clients][];
        BigInteger[] arrayResponse;
        for(int i=0;i<number_of_clients;i++){
            arrayResponse = (BigInteger[]) send(clients[i],8080,query);
            responseMatrix[i] = (arrayResponse);
        }

        //Task 3: aggregate the responses
        BigInteger[] aggregatedResponses = new BigInteger[length_of_response];
        BigInteger current_value;
        for(int j=0;j<length_of_response;j++){
            current_value = responseMatrix[0][j];
            //System.out.println(current_value.toString(10) + ";");

            for(int i=1;i<number_of_clients;i++){
                current_value = thresholdKey.add(current_value,responseMatrix[i][j]);
                //System.out.println(current_value.toString(10) + "!");

            }
            aggregatedResponses[j] = current_value;
        }

        //Task 4: distribute the aggregates and decipher
        BigInteger[] cleartextAggregates = new BigInteger[length_of_response];
        PartialDecryption currentZKP;
        for(int j=0;j<length_of_response;j++){
            PartialDecryption[] partialDecryptions = new PartialDecryption[number_of_clients];
            for(int i=0;i<clients.length;i++) {
                currentZKP = (PartialDecryption) send(clients[i], 8080, "e" + aggregatedResponses[j].toString(10));
                partialDecryptions[i] = currentZKP;
            }
            cleartextAggregates[j] = thresholdKey.combineShares(partialDecryptions);
        }
        //Task 5: Final processing.
        //order is cancer_events, cancer_total, normal_events, normal_total
        double numerator = ((cleartextAggregates[0].intValue()))*(cleartextAggregates[3].intValue());
        double denominator =(cleartextAggregates[1].intValue() * cleartextAggregates[2].intValue());
        double oddsRatio = numerator/denominator;
        System.out.println("The odds ratio is " + oddsRatio);
        String dummystring;
        for(int i=0;i<number_of_clients;i++){
            dummystring = (String) send(clients[i],port,"k");
        }
    }
}


