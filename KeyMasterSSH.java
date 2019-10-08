import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;

import paillierp.*;
import paillierp.key.*;
import paillierp.zkp.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class KeyMasterSSH {

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int port = 8080;

        //First let's set up the socket to communicate with the Aggregator.
        ServerSocket serverSocket = new ServerSocket(port);
        Socket socket = serverSocket.accept();
        OutputStream outputStream = socket.getOutputStream();
        InputStream inputStream = socket.getInputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        ObjectInputStream objectInputStream = new ObjectInputStream((inputStream));

        //We start by finding out how many keys we'll need
        int numberOfKeys = (int) objectInputStream.readObject();
        PublicKey[] publicKeys = new PublicKey[numberOfKeys];

        //We don't want to send private keys over plaintext, so let's get everyone's public key
        for(int i=0; i<numberOfKeys; i++){
            publicKeys[i] = (PublicKey) objectInputStream.readObject();
            System.out.println("KeyMaster: Public key " + i + " received");
        }

        SecureRandom rnd = new SecureRandom();
        PaillierPrivateThresholdKey[] keys = KeyGen.PaillierThresholdKey(40, numberOfKeys,numberOfKeys, rnd.nextLong());
        //NB-The Aggregator's key is currently necessary for decryption in order to protect the salts from exposure even in
        //the case of having only 2 clients.  This may be overly paranoid.


        PublicKey currentPublicKey;
        Cipher currentCipher;

        //Now we send out the keys and our job is done.
        for(int i = 0;i<numberOfKeys;i++){
            currentCipher = Cipher.getInstance("RSA");
            currentPublicKey = publicKeys[i];
            currentCipher.init(Cipher.ENCRYPT_MODE,currentPublicKey);
            objectOutputStream.writeObject(currentCipher.doFinal(keys[i].toByteArray()));
            System.out.println("KeyMaster: Paillier key " + i + " delivered");
        }

        socket.close();
        serverSocket.close();
        System.out.println("KeyMaster: Keys Delivered.  Signing off.");
    }
}