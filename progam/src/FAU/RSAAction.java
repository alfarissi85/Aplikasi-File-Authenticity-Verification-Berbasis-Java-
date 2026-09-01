package FAU;
import java.math.BigInteger;
import java.util.ArrayList;
public class RSAAction {
    
    //generate key
    private static KeyRSA KeyGenRSA;
    public static BigInteger PublicKey, privateKey, N;
    
    //function to set keys and N
    public static void generateKey(int bitlength){
        KeyGenRSA = new KeyRSA(bitlength);
        setPublicKey( KeyGenRSA.getE());
        setPrivateKey(KeyGenRSA.getD());
        setN(KeyGenRSA.getN());
    }
    private static void setPublicKey(BigInteger publicKey){
        RSAAction.PublicKey = publicKey;
    }
    
    private static void setPrivateKey(BigInteger privateKey){
        RSAAction.privateKey = privateKey;
    }
    
    private static void setN(BigInteger n){
        RSAAction.N = n;
    }
    
    public static BigInteger getPublicKey(){
        return RSAAction.PublicKey;
    }
    
    public static BigInteger getPrivateKey(){
        return RSAAction.privateKey;
    }
    
    public static BigInteger getN(){
        return RSAAction.N;
    }
    
    public static BigInteger[][] encrypt(BigInteger[][] ElGamalCipher, BigInteger key, BigInteger N) {
        BigInteger [][] cipher = new BigInteger[ElGamalCipher.length][ElGamalCipher.length];
        for(int i=0; i<ElGamalCipher.length; i++){
            cipher[i][0] = new BigInteger(ElGamalCipher[i][0].toString().getBytes()).modPow(key, N);
            cipher[i][1] = new BigInteger(ElGamalCipher[i][1].toString().getBytes()).modPow(key, N);

        }
        return cipher;
    }
    
    
//    for avalanche
    public static BigInteger[] encryptAvalanche(ArrayList plainInASCII, BigInteger key, BigInteger N){
        BigInteger[] cipher = new BigInteger[plainInASCII.size()];
        for(int i = 0; i<plainInASCII.size(); i++){
            cipher[i] = new BigInteger(plainInASCII.get(i).toString().getBytes()).modPow(key, N);
        }
        return cipher;
    }
    
    
    public static BigInteger[][] decrypt(BigInteger[][] cipher, BigInteger publicKeyRSA, BigInteger nRSA) {
        BigInteger[][] decrypted = new BigInteger[cipher.length][cipher.length];

        for(int i = 0; i<cipher.length; i++){
            decrypted[i][0] = new BigInteger(new String(cipher[i][0].modPow(publicKeyRSA, nRSA).toByteArray()));
            decrypted[i][1] = new BigInteger(new String(cipher[i][1].modPow(publicKeyRSA, nRSA).toByteArray()));
        }
        
        return decrypted;
    }
}
