
package FAU;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;


public class FAVUIController {
    
    public static String MD5HashFunction(String text) throws IOException{
        return MD5.md5DigestHexString(text);
    }
    
    public static long beginProcessingTime(){
        return System.nanoTime();
    }
    
    public static double endProcessingTime(long startTime){
        return (double) (System.nanoTime() - startTime);
    }
    
    public static String readFile(String path) throws FileNotFoundException, IOException{
        File file = new File(path);
        BufferedReader br = new BufferedReader(new FileReader(file));
        StringBuilder sb = new StringBuilder();
        String reader;
        // Condition holds true till
        // there is character in a string
        while ((reader = br.readLine()) != null){
            if(reader.length()==0)
                    //empty line
                sb.append("//@&.");
            else
                sb.append(reader);
        }
        
        return sb.toString();
    }
    
    public static String readFilePrint(String path) throws FileNotFoundException, IOException{
        File file = new File(path);
        BufferedReader br = new BufferedReader(new FileReader(file));
        StringBuilder sb = new StringBuilder();
        String reader;
        // Condition holds true till
        // there is character in a string
        while ((reader = br.readLine()) != null){
            if(reader.length()==0)
                    //empty line
                sb.append("\n");
            else
                sb.append(reader);
        }
        
        return sb.toString();
    }
    
    
    //signature will contain cipher(1st) with 8e7@ as line separator and @|p*4 as separator from alpha and beta.
    //Pu2S@ as separator for RSAPublicKey
    //nR5a as separator for RSA N value
    public static String generateSignature(String plaintext, int bitsize) throws IOException{
        String [] data = HybridCryptosystem.encrypt(plaintext, bitsize);
        return appendData(data);
    }
    
    public static String appendData(String[] data){
        return data[0] +"<1d3r" + data[1] + "Pu2S@" + data[2] + "nR5a" + data[3] + "43lg" + data[4] + "P31" + data[5];
    }
    
    public static String[] createSignatureFile(String data, String path){
        try{
            String fileName = path.substring(path.lastIndexOf("\\") + 1);
            String SignatureFileName = fileName.split("[.]")[0];
            File signatureFile = new File(SignatureFileName + "_signature.txt");
            String[] splittedPath = path.split("\\\\");
            String folderPath = splittedPath[0];

            for(int i = 1; i<splittedPath.length-1; i++){
                folderPath = folderPath + "\\" + splittedPath[i];
            }
            folderPath = folderPath + "\\";
            FileWriter fw = new FileWriter(folderPath + signatureFile);
            fw.write(data);
            fw.close();
            
            
            String[] info = new String [2];
            info [0] = "1";
            info [1] = folderPath + signatureFile;
            
            return info;
            
        }
        catch(Exception e){
            String[] info = new String [2];
            info [0] = "-1";
            info [1] = e.getMessage();
            return info;   
        }
    }
    
    public static void setReadonly(String path){
            File setReadonly = new File(path);
            setReadonly.setReadOnly();
    }
    
        public static String[] createSignatureFilePT(String data, String path){
        try{
            String fileName = path.substring(path.lastIndexOf("\\") + 1);
            String SignatureFileName = fileName.split("[.]")[0];
            File signatureFile = new File(SignatureFileName + "_signaturePT.txt");
            String[] splittedPath = path.split("\\\\");
            String folderPath = splittedPath[0];

            for(int i = 1; i<splittedPath.length-1; i++){
                folderPath = folderPath + "\\" + splittedPath[i];
            }
            folderPath = folderPath + "\\";
            FileWriter fw = new FileWriter(folderPath + signatureFile);
            fw.write(data);
            fw.close();
            
            String[] info = new String [2];
            info [0] = "1";
            info [1] = folderPath + signatureFile;
            return info;
            
        }
        catch(Exception e){
            String[] info = new String [2];
            info [0] = "-1";
            info [1] = e.getMessage();
            return info;   
        }
    }
    
    public static boolean verify(String a, String b){
        return a.equals(b);
    }
    
    public static String decrypt(String signature) throws IOException{
        return HybridCryptosystem.decrypt(signature);
    }
    
    public static String manipulateString(String input){
        String SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
        StringBuilder salt = new StringBuilder();
        Random rnd = new Random();
        while (salt.length() < 8) { // length of the random string.
            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
            salt.append(SALTCHARS.charAt(index));
        }
        String saltStr = salt.toString();
        
        int index = input.length()/2;
        
        String manipulated = input.substring(0, Math.min(input.length(), index)) + saltStr + input.substring(index, input.length());
        
        return manipulated;
    }
    
    public static String[] countAvalanche(String input1, String input2, int bitlength){
        //keygen
        AvalancheEffect.generateKey(bitlength);

        //conv to MD
        String MDIn1 = MD5.md5DigestHexString(input1);
        String MDIn2 = MD5.md5DigestHexString(input2);

        //convert md to ascii
        ArrayList cipher1 = AvalancheEffect.convertToASCII(MDIn1);
        ArrayList cipher2 = AvalancheEffect.convertToASCII(MDIn2);
        
        return AvalancheEffect.countAvalancheAll(cipher1, cipher2);
    }
}
