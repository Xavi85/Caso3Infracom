package seguridad;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SecurityFunctions {
	
	//El algoritmo simetrico de cifrado usa AES, CBC y esquema de relleno PKCS5Padding
	//con llave de 256 bits 
	private String algoritmo_simetrico = "AES/CBC/PKCS5Padding";
	//El algoritmo asimetricoo de cifrado usa RSA
	private String algoritmo_asimetrico = "RSA";
	
	//Este metodo genera la firma digital a partir de la llave privada 
    public byte[] sign(PrivateKey privada, String mensaje) throws Exception {
    	
    	//La firma se crea con SHA256withRSA
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        
        //Inicializa la firma para la llave privada recibida
        privateSignature.initSign(privada);
        //Agrega el mensaje a la firma
        privateSignature.update(mensaje.getBytes(StandardCharsets.UTF_8));
        
        //Devuelve la firma en bytes con la llave y el mensaje
        byte[] signature = privateSignature.sign();
        return signature;
    }
    
    //Verifica la confiabilidad de la firma recibida
    public boolean checkSignature(PublicKey publica, byte[] firma, String mensaje) throws Exception {
        
    	//Genera una firma publica, la cual se verifica con la llave publica 
    	Signature publicSignature = Signature.getInstance("SHA256withRSA");
    	//Inicia el objeto de verificacion con la llave publica
        publicSignature.initVerify(publica);
        
        //Agrega a la firma publica el mensaje generando asi la firma que debio haber
        //recibido
        publicSignature.update(mensaje.getBytes(StandardCharsets.UTF_8));
        
        //Compara la firma generada con el mensaje y la llave publica con la firma 
        //recibida. Retorna si son iguales 
        boolean isCorrect = publicSignature.verify(firma);
        return isCorrect;
    }
    
    //Cifra el mensaje a partir de una llave publica y con algoritmo asimetrico
    public byte[] aenc(PublicKey publica, String mensaje) throws Exception {  
    	
    	//Se genera el cifrador con el algoritmo_asimetrico
        Cipher encryptCipher = Cipher.getInstance(algoritmo_asimetrico);
        //Inicializa el cifrador con la llave publica
        encryptCipher.init(Cipher.ENCRYPT_MODE, publica);
        
        //Cifra el mensaje junto a la llave y retorna el mensaje cifrado
        byte[] cipherText = encryptCipher.doFinal(mensaje.getBytes());
        return cipherText;
    }
    
    //Descifra el mensaje a partir de una llave privada y con algoritmo asimetrico
    public String adec(byte[] cifrado, PrivateKey privada) throws Exception {
        
    	//Hace el descifrado con un algoritmo asimetrico
    	Cipher decriptCipher = Cipher.getInstance(algoritmo_asimetrico);
        //Descifra el mensaje con la llave privada
    	decriptCipher.init(Cipher.DECRYPT_MODE, privada);
    	
        //Descifra el mensaje cifrado y lo retorna
    	String decipheredMessage = new String(decriptCipher.doFinal(cifrado), StandardCharsets.UTF_8);
        System.out.println(decipheredMessage);
        return decipheredMessage;
    }
    
    //Algoritmo de creacion del hmac de un mensaje 
	public byte[] hmac(byte[] msg, SecretKey key) throws Exception {
		
		//El mac se hace con HMACSHA256
		Mac mac = Mac.getInstance("HMACSHA256");
		//Inicializa el Mac con la llave
		mac.init(key);
		
		//Retorna el mensaje de mac en bytes
		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}

	//Verifica que el mensaje no haya sido modificado a partir del mensaje original
	public boolean checkInt(byte[] msg, SecretKey key, byte [] hash ) throws Exception
	{
		//Crea un nuevo hmac a partir del mensaje y la llave 
		byte [] nuevo = hmac(msg, key);
		
		//Si es diferente el HMAC generado del recibido se dice que no son iguales
		if (nuevo.length != hash.length) {
			return false;
		}
		for (int i = 0; i < nuevo.length ; i++) {
			if (nuevo[i] != hash[i]) return false;
		}
		
		//Si son iguales se retorna true
		return true;
	}
    
	//Genera la llave para cifrado a partir de SHA-512
    public SecretKey csk1(String semilla) throws Exception {
    	byte[] byte_semilla = semilla.trim().getBytes(StandardCharsets.UTF_8);
    	MessageDigest digest = MessageDigest.getInstance("SHA-512");
    	byte[] encodedhash = digest.digest(byte_semilla);
    	byte[] encoded1 = new byte[32];
		for (int i = 0; i < 32 ; i++) {
			encoded1[i] = encodedhash[i];
		}
		SecretKey sk = null;
		sk = new SecretKeySpec(encoded1,"AES");	
		return sk;
	}
    
    //Genera la llave para el codigo de autentificacion HMAC
    public SecretKey csk2(String semilla) throws Exception {
    	byte[] byte_semilla = semilla.trim().getBytes(StandardCharsets.UTF_8);
    	MessageDigest digest = MessageDigest.getInstance("SHA-512");
    	byte[] encodedhash = digest.digest(byte_semilla);
    	byte[] encoded2 = new byte[32];
		for (int i = 32; i < 64 ; i++) {
			encoded2[i-32] = encodedhash[i];
		}
		SecretKey sk = null;
		sk = new SecretKeySpec(encoded2,"AES");	
		return sk;
	}
    
    
	//Cifra un mensaje por medio de algoritmo simetrico
	public byte[] senc (byte[] msg, SecretKey key, IvParameterSpec iv, String id) throws Exception {
		Cipher cifrador = Cipher.getInstance(algoritmo_simetrico); 
		long start = System.nanoTime();
		cifrador.init(Cipher.ENCRYPT_MODE, key, iv); 
		byte[] tmp = cifrador.doFinal(msg);
	    long end = System.nanoTime();      
	    System.out.println(id+" --- Elapsed Time for SYM encryption in nano seconds: "+ (end-start));   
		return tmp;
	}
	
	
	//Descifra un mensaje por medio de algoritmo simetrico
	public byte[] sdec (byte[] msg, SecretKey key, IvParameterSpec iv) throws Exception {
		Cipher decifrador = Cipher.getInstance(algoritmo_simetrico); 
		decifrador.init(Cipher.DECRYPT_MODE, key, iv); 
		return decifrador.doFinal(msg);
	}
	
	//Genera la llave publica 
	public PublicKey read_kplus(String nombreArchivo, String id) {
		FileInputStream is1;
		PublicKey pubkey = null;
		System.out.println(id+nombreArchivo);
		try {
			is1 = new FileInputStream(nombreArchivo);
			File f = new File(nombreArchivo);		
			byte[] inBytes1 = new byte[(int)f.length()];
			is1.read(inBytes1);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(inBytes1);
			pubkey = kf.generatePublic(publicKeySpec);
			is1.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return pubkey;
	}
	
	//Genera la llave privada
	public PrivateKey read_kmin(String nombreArchivo, String id) {
		PrivateKey privkey = null;
		System.out.println(id+nombreArchivo);
		FileInputStream is2;
		try {
			is2 = new FileInputStream(nombreArchivo);
			File f2 = new File(nombreArchivo);
			byte[] inBytes2 = new byte[(int)f2.length()];
			is2.read(inBytes2);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(inBytes2);
			privkey = kf.generatePrivate(privateKeySpec);
			is2.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return privkey;
	}


}
