package FAU;

import java.util.*;
import java.math.*;
import java.security.*;

public class ElGamalAction {
    private static KeyElGamal KeyGenElGamal;
    public static String publicKey, privateKey;
   
    //generate key for elgamal. Take the generated key from KeyElgamal
    public static void GenerateKey(){
        KeyGenElGamal = new KeyElGamal();
        setPublicKey(KeyGenElGamal.getPublicKey());
        setPrivateKey(KeyGenElGamal.getPrivateKey());
    }
    
    //the key format for publickey is (beta%alpha%P) and for private key is (A%P)
    //this function is to split the string and remove the "%"
    public static BigInteger splitKey(String Key, int index){
        String[] splitted = Key.split("@dt@");
        return new BigInteger(splitted[index]);
    }
    
    private static void setPublicKey(String key){
        ElGamalAction.publicKey = key;
    }
    
    private static void setPrivateKey(String key){
        ElGamalAction.privateKey = key;
    }
    
    public static String getPublicKey(){
        return ElGamalAction.publicKey;
    }
    
    public static String getPrivateKey(){
        return ElGamalAction.privateKey;
    }
    
    public static BigInteger[][] encrypt(ArrayList arrStr, String key){
        //Key Splitting 
        BigInteger beta = splitKey(key, 0);
        BigInteger alpha = splitKey(key, 1);
        BigInteger p = splitKey(key, 2);
        SecureRandom rand = new SecureRandom();
        //create array to contain the cipher. [i][0] will contain the cipher of alpha^r mod P
        //[i][1] will contain the cipher of beta^k m mod P
        BigInteger [][] cipher = new BigInteger[arrStr.size()][arrStr.size()];
        BigInteger r = BigInteger.ZERO;
        for(int i = 0; i<arrStr.size(); i++){
            do{
            r = new BigInteger(160, 100, rand);
            } while(r.compareTo(BigInteger.ZERO) == -1 || r.compareTo(p.subtract(new BigInteger("2"))) == 1); 
            BigInteger betaR = beta.modPow(r, p);
            BigInteger alphaM = alpha.modPow(new BigInteger(arrStr.get(i).toString()), p);
            cipher[i][0] = alpha.modPow(r, p);
            cipher[i][1] = betaR.multiply(alphaM);
        }
        return cipher;
    }
    
        public static BigInteger[] encryptAvalanche(ArrayList arrStr, String key){
        //Key Splitting 
        BigInteger beta = splitKey(key, 0);
        BigInteger alpha = splitKey(key, 1);
        BigInteger p = splitKey(key, 2);
        SecureRandom rand = new SecureRandom();
        //create array to contain the cipher. [i][0] will contain the cipher of alpha^r mod P
        //[i][1] will contain the cipher of beta^k m mod P
        BigInteger [][] cipher = new BigInteger[arrStr.size()][arrStr.size()];
        BigInteger [] returncipher  =new BigInteger[arrStr.size()];
        BigInteger r = BigInteger.ZERO;
        for(int i = 0; i<arrStr.size(); i++){
            do{
            r = new BigInteger(160, 100, rand);
            } while(r.compareTo(BigInteger.ZERO) == -1 || r.compareTo(p.subtract(new BigInteger("2"))) == 1); 
            BigInteger betaR = beta.modPow(r, p);
            BigInteger alphaM = alpha.modPow(new BigInteger(arrStr.get(i).toString()), p);
            cipher[i][0] = alpha.modPow(r, p);
            cipher[i][1] = betaR.multiply(alphaM);
            returncipher[i] = new BigInteger(cipher[i][0].toString() + cipher[i][1].toString());
        }
        
        
        return returncipher;
    }
    
//    //used for avalanche cause the avalanche only use 1 dimension array
//        public static BigInteger[] encryptAvalanche(String message){
//        ArrayList arrStr = convToAscii(message);
//        SecureRandom rand = new SecureRandom();
//        BigInteger [][] cipher = new BigInteger[arrStr.size()][arrStr.size()];
//        BigInteger r = BigInteger.ZERO;
//        for(int i = 0; i<arrStr.size(); i++){
//            do{
//            r = new BigInteger(160, 100, rand);
//            } while(r.compareTo(BigInteger.ZERO) == -1 || r.compareTo(getP().subtract(new BigInteger("2"))) == 1); 
//            BigInteger betaR = getBeta().modPow(r, getP());
//            BigInteger alphaM = getAlpha().modPow(new BigInteger(arrStr.get(i).toString()), getP());
//            cipher[i][0] = getAlpha().modPow(r, getP());
//            cipher[i][1] = betaR.multiply(alphaM);
//        }
//        return appendAlphaBeta(cipher);
//    }
       
        
    public static String decrypt(BigInteger[][] cipher, BigInteger aEl, BigInteger pEl, BigInteger alphaEl){
        ArrayList plain = new ArrayList();
        for(int i = 0; i<cipher.length; i++){
            BigInteger betaR = cipher[i][0].modPow(aEl, pEl);
            BigInteger alphaM = cipher[i][1].multiply(betaR.modInverse(pEl)).mod(pEl); 
            BigInteger index = BigInteger.ONE;
            BigInteger alphaMPrime = alphaEl.modPow(index, pEl); 
            while(alphaMPrime.equals(alphaM) == false){
                index = index.add(BigInteger.ONE);
                alphaMPrime = alphaEl.modPow(index, pEl);
            }
            plain.add(index);
        }
           
        for(int i = 0; i<plain.size(); i++){
            plain.set(i, (char) Integer.parseInt(plain.get(i).toString())); 
        }
        
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < plain.size(); i++) {
           sb.append(plain.get(i));
        }
        return sb.toString();
    }
}
