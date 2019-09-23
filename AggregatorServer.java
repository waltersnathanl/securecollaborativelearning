package club.securecollaborativelearning;

import paillierp.PaillierThreshold;
import paillierp.key.KeyGen;
import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.zkp.DecryptionZKP;

import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Random;

    public class AggregatorServer{
        public static void main(String[] args) throws IOException, ClassNotFoundException {
            //Task 1: get a list we can use to communicate with all the clients.
            InetAddress[] clients = new InetAddress [1];
//            clients[0] = InetAddress.getByName("34.211.230.198");
            clients[0] = InetAddress.getByName("34.223.215.79");


            //Task 1: generate and distribute keys
            Random rnd = new Random();
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


            //Task 2: distribute the query and acquire coded responses
            //subtask 1: create the query
            String query = "qSELECT cancer_events, cancer_total, normal_events, normal_total FROM healthdata;&&&cancer_events:1&&&cancer_total:1&&&normal_events:1&&&normal_total:1";
            int length_of_response = 4;  //I'm not sure what we'll do if not hardcode every query.

            //subtask 2: collect encrypted responses
            BigInteger[][] responseMatrix = new BigInteger[clients.length][];
            BigInteger[] arrayResponse;
            for(int i=0;i<clients.length;i++){
                try (Socket socket = new Socket(clients[i],8080)){
                    OutputStream outputStream = socket.getOutputStream();
                    InputStream inputStream = socket.getInputStream();
                    ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
                    ObjectInputStream objectInputStream1 = new ObjectInputStream(inputStream);  //Hashtag
                    objectOutputStream.writeObject(query);
                    arrayResponse = new BigInteger[0];
                    while(objectInputStream1.available()>0){
                        arrayResponse = (BigInteger[]) objectInputStream1.readObject();
                    }
                    responseMatrix[i] = (arrayResponse);
                }
            }
            //Task 3: aggregate the responses
            BigInteger[] aggregatedResponses = new BigInteger[length_of_response];
            for(int j=0;j<length_of_response;j++){
                BigInteger current_value = responseMatrix[0][j];
                for(int i=1;i<clients.length;i++){
                    current_value = myKey.add(current_value,responseMatrix[i][j]);
                }
                aggregatedResponses[j] = current_value;
            }

            //Task 4: distribute the aggregates and decipher
            BigInteger[] cleartextAggregates = new BigInteger[length_of_response];
            DecryptionZKP currentZKP;
            for(int j=0;j<length_of_response;j++){
                DecryptionZKP[] partialDecryptions = new DecryptionZKP[clients.length];
                for(int i=0;i<clients.length;i++){
                    try (Socket socket = new Socket(clients[i], 8080)) {
                        OutputStream outputStream = socket.getOutputStream();
                        InputStream inputStream = socket.getInputStream();
                        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
                        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
                        objectOutputStream.writeObject("e" + aggregatedResponses.toString());
                        while(objectInputStream.available()>0){
                            currentZKP = (DecryptionZKP) objectInputStream.readObject();
                            partialDecryptions[i] = currentZKP;
                        }
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                }
                cleartextAggregates[j] = myKey.combineShares(partialDecryptions);
            }
            //Task 5: Final processing.
            //order is cancer_events, cancer_total, normal_events, normal_total
            double numerator = ((cleartextAggregates[0].intValue()))*(cleartextAggregates[3].intValue());
            double denominator =(cleartextAggregates[1].intValue() * cleartextAggregates[2].intValue());
            double oddsRatio = numerator/denominator;
            System.out.println("The odds ratio is " + oddsRatio);
            for(int i=0;i<clients.length;i++){
                try (Socket socket = new Socket(clients[i],8080)){
                    OutputStream outputStream = socket.getOutputStream();
                    InputStream inputStream = socket.getInputStream();
                    ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
                    ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
                    objectOutputStream.writeObject("k");
                    currentResponse = (String) objectInputStream.readObject();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
            }
        }
    }


