package FAU;

import java.math.BigInteger;
import java.text.DecimalFormat;
import java.util.ArrayList;

public class AvalancheEffect {
    private static final DecimalFormat df = new DecimalFormat("0.00");
    private static BigInteger keyRSA;
    private static String keyElgamal;
    private static BigInteger NRSA;
    private static int bitlength;

    public static void generateKey(int bitlength) {
        setBitLength(bitlength);
        
        //keyGen for Elgamal
        ElGamalAction.GenerateKey();
        //get elgamal keys
        setKeyElgamal(ElGamalAction.getPublicKey());
        
        //KeyGen for RSA
        RSAAction.generateKey(getBitLength());
        //Key components for RSA
        setKeyRSA(RSAAction.getPrivateKey());
        setNRSA(RSAAction.getN());
    }
    
    private static void setNRSA(BigInteger NRSA){
        AvalancheEffect.NRSA = NRSA;
    }
    
    private static void setKeyRSA(BigInteger KeyRSA){
        AvalancheEffect.keyRSA = KeyRSA;
    }

    private static void setKeyElgamal(String KeyElgamal){
        AvalancheEffect.keyElgamal = KeyElgamal;
    }
    
    private static void setBitLength(int bitlength){
        AvalancheEffect.bitlength = bitlength;
    }
    
    private static String getKeyElgamal(){
        return AvalancheEffect.keyElgamal;
    }
    
    private static BigInteger getKeyRSA(){
        return AvalancheEffect.keyRSA;
    }
    
    private static BigInteger getNRSA(){
        return AvalancheEffect.NRSA;
    }
    
    private static int getBitLength(){
        return AvalancheEffect.bitlength;
    }
    
    public static ArrayList convertToASCII(String input){
        ArrayList split = new ArrayList(); 
        for(int i = 0; i < input.length(); i++){
            char tempc = input.charAt(i);
            int tempi = (int) tempc;
            BigInteger tmp = new BigInteger(Integer.toString(tempi));
            split.add(tmp);
        } 
        return split;
    }
    
    private static  int cipherInBinaryLength(BigInteger[] cipher){
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i<cipher.length; i++){
            sb.append(new BigInteger(cipher[i].toString(2)));
        }
        return sb.toString().length();
    }
    
    //used for the divider of avalanche
    private static int getMostStrLength(BigInteger[] cipher1, BigInteger[] cipher2){        
        if(cipherInBinaryLength(cipher1)<cipherInBinaryLength(cipher2))
            return cipherInBinaryLength(cipher2);
        else
            return cipherInBinaryLength(cipher1);
    }
    
    //used for the xor 'for' operation limit
    private static int getLeastArrLength(BigInteger[] cipher1, BigInteger[] cipher2){
        if(cipher1.length>cipher2.length)
            return cipher2.length;
        else
            return cipher1.length;
    }
    
    private static String xorOperation(BigInteger[] cipher1, BigInteger[] cipher2){
        int index = getLeastArrLength(cipher1, cipher2);
        StringBuilder sbxor = new StringBuilder();
        for(int i = 0; i<index; i++){
            sbxor.append(cipher1[i].xor(cipher2[i]).toString(2));
        }
        //convert sbxor of bigintegers into string
        return sbxor.toString();
    }
    
    private static int count1(String xor){
        int count1 = 0;
        for(int i = 0; i<xor.length(); i++){
            if(xor.charAt(i) == '1')
                count1++;
        }
        return count1;
    }
    
    private static double countAvalanche(BigInteger[] cipher1, BigInteger[] cipher2){
        
        String xor = xorOperation(cipher1, cipher2);
        int count1 = count1(xor);
        int divider = getMostStrLength(cipher1, cipher2);
        
        //count avalanche and rounding it
        double avalanche = ((double) count1/ (double) divider) *100;
        return  Double.parseDouble(df.format(avalanche));
    }
    
    private static double RSAAvalanche(ArrayList input1, ArrayList input2){
        //RSA encrypt process
        BigInteger[] cipher1BI = RSAAction.encryptAvalanche(input1, getKeyRSA(), getNRSA());
        BigInteger[] cipher2BI = RSAAction.encryptAvalanche(input2, getKeyRSA(), getNRSA());

        
        return countAvalanche(cipher1BI, cipher2BI);
    }
    
    public static String [] countAvalancheAll(ArrayList input1, ArrayList input2){
                String [] data = new String[3];
                data[0] = df.format(ElGamalAvalanche(input1, input2));
                data[1] = df.format(RSAAvalanche(input1, input2));
                data[2] = df.format(HybridAvalanche(input1, input2));
                
        return data;
    }
    
    private static double ElGamalAvalanche(ArrayList input1, ArrayList input2){
        BigInteger[] cipher1BI = ElGamalAction.encryptAvalanche(input1, getKeyElgamal());
        BigInteger[] cipher2BI = ElGamalAction.encryptAvalanche(input2, getKeyElgamal());
        
        return countAvalanche(cipher1BI, cipher2BI);
    }
    
    private static double HybridAvalanche(ArrayList input1, ArrayList input2){
        BigInteger[] cipher1BI = HybridCryptosystem.encryptAvalanche(input1, getKeyElgamal(), getKeyRSA(), getNRSA());
        BigInteger[] cipher2BI = HybridCryptosystem.encryptAvalanche(input2, getKeyElgamal(), getKeyRSA(), getNRSA());
        
        return countAvalanche(cipher1BI, cipher2BI);
    }
}
