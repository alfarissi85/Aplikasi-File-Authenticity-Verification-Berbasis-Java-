package FAU;
import java.io.UnsupportedEncodingException;
import java.math.*;
import java.security.*;
import java.util.Arrays;

public final class KeyRSA {
    private BigInteger p;
    private BigInteger q;
    public BigInteger n;
    private BigInteger phiN;
    public BigInteger e;
    public BigInteger d;
    private int  bitlength = 1024;
    SecureRandom R = new SecureRandom();

    public KeyRSA(){
        generateP();
        generateQ();
        generateN();
        generatePhiN();
        generateE();
        generateD();
    } 
    
    public KeyRSA(int bitLength){
        setBitLength(bitLength);
        generateP();
        generateQ();
        generateN();
        generatePhiN();
        generateE();
        generateD();
    }
    
    public void generateP(){
        BigInteger plocal = new BigInteger(getBitLength()/2, 100, getR());
        BigInteger divider = BigInteger.valueOf(2);
        
        if (plocal.isProbablePrime((plocal.divide(divider)).intValue()) == true){
            setP(plocal);
        }
        else{
            generateP();
        }
        
        
    }
    
    public void generateQ(){
        BigInteger qlocal = new BigInteger(getBitLength()/2, 100, getR());
        BigInteger divider = BigInteger.valueOf(2);
        
        if (qlocal.isProbablePrime((qlocal.divide(divider)).intValue()) == true && getP().equals(qlocal) == false){
            setQ(qlocal);
        }
        else{
            generateQ();
        }
    }
    
    public void generateN(){
        setN(getP().multiply(getQ()));
    }
    
    public void generatePhiN(){
        setPhiN((getP().subtract(BigInteger.ONE)).multiply((getQ().subtract(BigInteger.ONE))));
    }
    
    public void generateE(){
        BigInteger elocal = new BigInteger(getBitLength()/2, 100, getR());
        BigInteger gcd = elocal.gcd(getPhiN());

        while(elocal.compareTo(getPhiN()) == 1 
              || elocal.compareTo(BigInteger.ONE) == -1 || gcd.equals(BigInteger.ONE) == false){
            generateE();
    }
        setE(elocal);
    }
    
    public BigInteger gcd(BigInteger e, BigInteger phiN) {
        if (phiN.equals(BigInteger.ZERO) == true){
            return e;
        }
        return gcd(phiN,e.mod(phiN));
    }
    
//    public void generateD(){
//        SecureRandom rand = new SecureRandom();
//        BigInteger dlocal = new BigInteger(getBitLength()/2, 100, rand);
//
//        System.out.println(gcdExtended(dlocal, getE(), BigInteger.ONE, BigInteger.ONE));
//        while(gcdExtended(dlocal, getE(), BigInteger.ONE, BigInteger.ONE).equals(BigInteger.ONE) == false){
//            generateD();
//        }
//        
//        setD(dlocal);
//        
//    }
    
    public void generateD(){
        setD(getE().modInverse(getPhiN()));
    }

    
//    public static BigInteger gcdExtended(BigInteger d, BigInteger e, BigInteger x, BigInteger y)
//    {
//        // Base Case
//        if (d.equals(BigInteger.ZERO) == true) {
//            x = BigInteger.ZERO;
//            y = BigInteger.ONE;
//            return e;
//        }
//  
//        BigInteger x1 =  BigInteger.ONE, y1 = BigInteger.ONE; // To store results of recursive call
//        BigInteger gcd = gcdExtended(e.mod(d), d, x1 , y1);
//  
//        // Update x and y using results of recursive
//        // call
//        x = y1.subtract((e.mod(d).multiply(x1)));
//        y = x1;
//  
//        return gcd;
//    }
    
    public BigInteger getP(){
        return this.p;
    }
    
    public BigInteger getQ(){
        return this.q;
    }
    
    public BigInteger getN(){
        return this.n;
    }
    
    public BigInteger getPhiN(){
        return this.phiN;
    }
    
    public BigInteger getE(){
        return this.e;
    }
    
     public BigInteger getD(){
        return this.d;
    }
     
     public int getBitLength(){
         return this.bitlength;
     }
     
     private SecureRandom getR(){
         return this.R;
     }
     
     
    private void setP(BigInteger p){
        this.p = p;
    }
    
    private void setQ(BigInteger q){
        this.q = q;
    }
    
    private void setN(BigInteger n){
        this.n = n;
    }
    
    private void setPhiN(BigInteger phiN){
        this.phiN = phiN;
    }
    
    private void setE(BigInteger e){
        this.e = e;
    }
    
    private void setD(BigInteger d){
        this.d = d;
    }
    
    private void setBitLength(int bitLength){
        this.bitlength = bitLength;
    }
}
