package FAU;

import java.util.*;
import java.math.*;
import java.security.*;

public class HybridCryptosystem {
    
        //split and convert the message into array of big integers (in ASCII)
    private static ArrayList convertToASCII(String input){
        ArrayList split = new ArrayList(); 
        for(int i = 0; i < input.length(); i++){
            char tempc = input.charAt(i);
            int tempi = (int) tempc;
            BigInteger tmp = new BigInteger(Integer.toString(tempi));
            split.add(tmp);
        } 
        return split;
    }
        
    public static String[] encrypt(String plaintext, int bitlength){
        //=============================MD===========================
        //creating MD
        String MD = MD5.md5DigestHexString(plaintext);
        
        //convert message to ascii
        ArrayList arrStr = convertToASCII(MD);
        
        //=============================Elgamal===========================
        //keyGen for Elgamal
        ElGamalAction.GenerateKey();
        //get elgamal keys
        String elPubKey = ElGamalAction.getPublicKey();
        String elPrivKey = ElGamalAction.getPrivateKey();
        //components for elgamal decrypt
        String AEl = ElGamalAction.splitKey(elPrivKey, 0).toString();
        String AlphaEl = ElGamalAction.splitKey(elPubKey, 1).toString();
        String PEl = ElGamalAction.splitKey(elPubKey, 2).toString();

        //elgamal encrypt process
            BigInteger[][] result = ElGamalAction.encrypt(arrStr, elPubKey);
        
        //=============================RSA===========================
        //keygen for RSA
        RSAAction.generateKey(bitlength);
        //components for RSA decrypt
        BigInteger PrivateKeyRSA = RSAAction.getPrivateKey();
        BigInteger PublicKeyRSA = RSAAction.getPublicKey();
        BigInteger NRSA = RSAAction.getN();
        //RSA encrypt process
        result = RSAAction.encrypt(result, PrivateKeyRSA, NRSA);
        
        String sb = new String();
        for (BigInteger[] cipher1 : result) {
            sb = sb + cipher1[0] + "@lp4" + cipher1[1] + "8e7@";
        } 
        
        String[] data = new String[6];
        data[0] = sb;
        data[1] = PublicKeyRSA.toString();
        data[2] = NRSA.toString();
        data[3] = AEl;
        data[4] = PEl;
        data[5] = AlphaEl;
        
        return data;
    }
    
    public static BigInteger[] encryptAvalanche(ArrayList plaintext, String keyElgamal, BigInteger keyRSA, BigInteger NRSA){

        //elgamal encrypt process
            BigInteger[] result = ElGamalAction.encryptAvalanche(plaintext, keyElgamal);

            ArrayList resultarrl = new ArrayList();
            
            for(int i = 0; i<result.length; i++){
                resultarrl.add(result[i]);
            }
        //RSA encrypt process
        result = RSAAction.encryptAvalanche(resultarrl, keyRSA, NRSA);
        
        return result;
    }
    
//        public static BigInteger[] encryptAvalanche(String plain){
//        setPlainText(plain);
//        createMessageDigest();
//        ElGamalAction.GenerateKey();
//        ElGamalAction.encrypt(getMessageDigest());
//        setCipherText(ElGamalAction.getCipherText());
//        RSAAction.generateKey();
//        RSAAction.encrypt(getCipherText());
//        return appendAlphaBeta(RSAAction.getCipherText());
//    }
    
    public static String decrypt(String signature){
        String cipherStr = signature.split("<1d3r")[0];
        BigInteger publicKeyRSA = new BigInteger(signature.split("<1d3r")[1].split("Pu2S@")[0]);
        BigInteger nRSA = new BigInteger(signature.split("<1d3r")[1].split("Pu2S@")[1].split("nR5a")[0]);
        BigInteger aEl = new BigInteger(signature.split("<1d3r")[1].split("Pu2S@")[1].split("nR5a")[1].split("43lg")[0]);
        BigInteger pEl = new BigInteger(signature.split("<1d3r")[1].split("Pu2S@")[1].split("nR5a")[1].split("43lg")[1].split("P31")[0]);
        BigInteger alphaEl = new BigInteger(signature.split("<1d3r")[1].split("Pu2S@")[1].split("nR5a")[1].split("43lg")[1].split("P31")[1]);
        
        String [] temp = cipherStr.split("8e7@");
        BigInteger[][] cipher = new BigInteger[temp.length][temp.length];
        for(int i = 0; i<cipher.length; i++){
            cipher[i][0] = new BigInteger(temp[i].split("@lp4")[0]);
            cipher[i][1] = new BigInteger(temp[i].split("@lp4")[1]);
        }
        cipher = RSAAction.decrypt(cipher, publicKeyRSA, nRSA);
        String decryptedMessage = ElGamalAction.decrypt(cipher, aEl, pEl, alphaEl);
        
        return decryptedMessage;
    }
}
