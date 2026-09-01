package FAU;

import java.util.*;
import java.math.*;
import java.security.*;


public final class KeyElGamal {
    private BigInteger p;
    private BigInteger alpha; //g
    private BigInteger a; //x
    private BigInteger beta; //h
    private final int bitlength = 160;
    public String publicKey, privateKey;
    SecureRandom R = new SecureRandom();

    
    //generate key
    public KeyElGamal(){
        generateP();
        generateAlpha();
        generateA();
        generateBeta();
        generatePublicKey();
        generatePrivateKey();
    }
    
    private void generateP(){
        SecureRandom rand = new SecureRandom();
        BigInteger plocal= new BigInteger(getBitLength(), 100, rand);
        BigInteger divider = BigInteger.valueOf(2);

        if (plocal.isProbablePrime((plocal.divide(divider)).intValue()) == true && plocal.compareTo(BigInteger.valueOf(255)) == 1){
            setP(plocal);
        }
        else{
            generateP();
        }
    }
    
    private void generateAlpha(){
        SecureRandom rand = new SecureRandom();
        BigInteger alphalocal= new BigInteger(getBitLength(), 100, rand);
        BigInteger divider = BigInteger.valueOf(2);

        if (alphalocal.isProbablePrime((alphalocal.divide(divider)).intValue()) == true && alphalocal.compareTo(getP()) == -1){
            setAlpha(alphalocal);
        }
        else{
            generateAlpha();
        }
    }
    
    private void generateA(){
        SecureRandom rand = new SecureRandom();
        BigInteger alocal = new BigInteger(getBitLength(), 100, rand);
        BigInteger divider = BigInteger.valueOf(2);
        if (alocal.isProbablePrime((alocal.divide(divider)).intValue()) == true && alocal.compareTo(getP().subtract(divider)) == -1 && alocal.compareTo(BigInteger.ONE) == 1){
            setA(alocal);
        }
        else{
            generateA();
        }
    }
    
    private void generateBeta(){
        BigInteger betalocal = getAlpha().modPow(getA(), getP());
        setBeta(betalocal);
    }
    
    private void generatePublicKey(){
        String key = getBeta() + "@dt@" + getAlpha() + "@dt@" + getP();
        setPublicKey(key);
    }
    
    private void generatePrivateKey(){
        String key = getA() + "@dt@" + getP();
        setPrivateKey(key);
    }
    
    private BigInteger getP(){
        return this.p;
    }
    
    private BigInteger getAlpha(){
        return this.alpha;
    }
    
    private BigInteger getA(){
        return this.a;
    }
    
    private BigInteger getBeta(){
        return this.beta;
    }
    
    private int getBitLength(){
        return this.bitlength;
    }
    
    public String getPublicKey(){
        return this.publicKey;
    }
     public String getPrivateKey(){
        return this.privateKey;
    }
    
    
    private void setP(BigInteger p){
        this.p = p;
    }
    
    private void setAlpha(BigInteger alpha){
        this.alpha = alpha;
    }
    
    private void setA(BigInteger a){
        this.a = a;
    }
    
    private void setBeta(BigInteger beta){
        this.beta = beta;
    }
 
    private void setPublicKey(String publicKey){
        this.publicKey = publicKey;
    }
    private void setPrivateKey(String privateKey){
        this.privateKey = privateKey;
    }
}
    
