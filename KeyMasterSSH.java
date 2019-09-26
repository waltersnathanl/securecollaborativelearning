import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;

import paillierp.*;
import paillierp.key.*;
import paillierp.zkp.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class KeyMasterSSH {
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

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //if (args.length < 1) return;
        //int port = Integer.parseInt(args[0]);
        int port = 8080;

        InetAddress[] addresses = (InetAddress[]) get(port, "confirmed");
        int numberOfKeys = addresses.length;
        //For now, we will make it so all clients can work together to decrypt the aggregates.  Ideally we would
        //make the aggregator unable to participate, but at the moment it seems difficult to make a true public key
        //using the Paillier package, and it's not worth the time it would take to fix it.  Instead we will ignore
        //that functionality of the aggregator's key

        SecureRandom rnd = new SecureRandom();
        PaillierPrivateThresholdKey[] keys = KeyGen.PaillierThresholdKey(128, numberOfKeys,numberOfKeys-1, rnd.nextLong());

        Object junk;

        //Now let's get everyone's public key and send them an encrypted key for Paillier
        PublicKey[] publicKeys = new PublicKey[addresses.length];
        Cipher currentCipher;
        for(int i = 1;1<numberOfKeys;i++){
            junk = send(addresses[i],port,addresses[numberOfKeys-1]);
            publicKeys[i] = (PublicKey) send(addresses[i],port,"Public Key?");
            currentCipher = Cipher.getInstance("RSA");
            currentCipher.init(Cipher.ENCRYPT_MODE,publicKeys[i]);
            junk = send(addresses[i],port,currentCipher.doFinal(keys[i].toByteArray()));
        }

        System.out.println("Keys Delivered.  Signing off.");
    }
}

