package seguridad;

import java.io.BufferedReader;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ClienteThread extends Thread{

	//Constantes
	
	
	//Atributos
	private int idCliente;
	private Socket sc;
	private SecurityFunctions f;
	private String dlg;
	private BigInteger p;
	private BigInteger g;
	
	
	//Metodo constructor 
	//Recibe el lector de lo que escribe el cliente, de lo que devuelve el servidor, escritor de lo que
	//envia al servidor, y el id de cliente.
	public ClienteThread (Socket pSc, int pIdCliente)
	{
		sc = pSc;
		idCliente = pIdCliente;
		
		//Se usa dlg porque este afecta a la creacion de la llave privada 
		dlg = new String("concurrent server " + idCliente + ": ");
		//Se inicializa el llamado a las funciones
		f = new SecurityFunctions();
	}
	
	
	//Aca empieza a correr el codigo del thread 
	public void run()
	{
		//Se va a retornar si fueron exitosas las operaciones con el servidor 
		boolean exito = true;
		
		String linea;
		System.out.println("Starting client communication.");
	    
		
		try 
		{
			//Crea la comunicacion entre el servidor y el cliente 
			PrintWriter escritor = new PrintWriter(sc.getOutputStream(), true);
			BufferedReader lector = new BufferedReader(new InputStreamReader(sc.getInputStream()));
			//Inicialmente necesitamos tener presente que el thread de cliente conoce la llave del servidor
			//por lo que se crea igual a como se creo en el servidor
			PublicKey publicaServidor = f.read_kplus("datos_asim_srv.pub",dlg);
			
			//Primero que todo envia un mensaje de iniciacion al servidor 
			escritor.println("SECURE INNIT");
			
			//Luego revise los parametros para el DH generados por el servidor
			//Obtiene g
			linea = lector.readLine();
			g = new BigInteger(linea);
			//Obtiene p
			linea = lector.readLine();
			p = new BigInteger(linea);
			//Obtiene valor comun G^x
			linea = lector.readLine();
			BigInteger g2x = new BigInteger(linea);
			
			
			//A continuacion hace la verificacion de la firma que recibe 
			
			//Primero se genera el mismo mensaje que se hizo en la firma a partir de g, p y G^x, 
			//para llevar a cabo la verificacion
			String msj = g.toString()+","+p.toString()+","+g2x.toString();
			
			//Luego tiene que recibir la firma 
			linea = lector.readLine();
			byte[] byteauthentication = str2byte(linea);
			
			//Ahora verifica la firma a partir de la funcion definida en SecurityFunction
			boolean respAut = f.checkSignature(publicaServidor, byteauthentication, msj);
			
			//Retorna finalmente mensaje de error o confirmacion
			if(respAut)
			{
				escritor.println("OK");
				
				//Lo siguiente es enviar G^Y
				
				//Definimos y como un valor random en BigInteger, asi como se calculo X
				SecureRandom r = new SecureRandom();
				int y = Math.abs(r.nextInt());
	    		Long longy = Long.valueOf(y);
	    		BigInteger biy = BigInteger.valueOf(longy);
	    		
	    		//Calculamos G^y a partir de la funcion definida abajo
	    		BigInteger valor_comun = G2Y(g,biy,p);
	    		String str_valor_comun = valor_comun.toString();
	    		
	    		//Enviamos G^y al servidor para que pueda crear la llave maestra 
	    		escritor.println(str_valor_comun);
	    		
	    		//Calculamos la llave maestra
	    		// computing (G^x)^y mod N
	    		BigInteger llave_maestra = calcular_llave_maestra(g2x,biy,p);
	    		String str_llave = llave_maestra.toString();
	    		System.out.println(dlg + " llave maestra: " + str_llave);
				
	    		//A partir de la llave maestra se calcula la llave simetrica de cifrado y HMAC
	    		SecretKey sk_cliente = f.csk1(str_llave);
				SecretKey sk_mac = f.csk2(str_llave);
				
				//De igual manera, se calcula iv_1
				byte[] iv1 = generateIvBytes();
	        	String str_iv1 = byte2str(iv1);
				IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);
				
				
				
				//Enviar un mensaje cifrado y el HMAC
				
				//Primero se envia el numero random 
				Random aleatorio = new Random();
				Integer random = aleatorio.nextInt((Integer.MAX_VALUE-1)+1);
				String valor = String.valueOf(random);
				
				
				//Enviar mensaje cifrado con la llave simetrica de cifrado
					
				//Pasamos a bytes el valor ingresado por la persona
				byte[] byte_valor = valor.getBytes();
					
				//Generamos el mensaje cifrado para la consulta
				byte[] consulta = f.senc(byte_valor, sk_cliente,ivSpec1, "Cliente");
				//Genera el hmac del mensaje que se envia cifrado
		        byte [] hmac = f.hmac(byte_valor, sk_mac);
		        //Los convierte a string para ser enviados
		        String m1 = byte2str(consulta);
		        String m2 = byte2str(hmac);
		        //Envia al servidor
		        escritor.println(m1);
		        escritor.println(m2);
		        escritor.println(str_iv1);
		        
		        
		        //El cliente recibe la respuesta de si fue correcta la comunicacion del mensaje cifrado
		        //con su HMAC
		        linea = lector.readLine();
    			if (linea.compareTo("OK")==0) {
    				System.out.println("==========> client sends matching query and MAC");
    			} else if (linea.compareTo("ERROR")==0) {
    				System.out.println("==========> failed client sends matching query and MAC");
    				exito = false;
    			}
		        
		        
		        
		        //Recibir el mensaje de respuesta, hmac y iv a partir del cual revisa que se haya cumplido
		        //la verificacion
		        String str_rtaconsulta = lector.readLine();
				String str_rtamac = lector.readLine();
				String str_iv2 = lector.readLine();
				byte[] byte_rtaconsulta = str2byte(str_rtaconsulta);
				byte[] byte_mac = str2byte(str_rtamac);
				
				byte[] iv2 = str2byte(str_iv2);
				IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);
		    	byte[] descifrado = f.sdec(byte_rtaconsulta, sk_cliente,ivSpec2);
		    	boolean verificar = f.checkInt(descifrado, sk_mac, byte_mac);
				System.out.println(dlg + "Integrity check:" + verificar);  
				
				if (verificar) {
		    		System.out.println("==========> Test: passed Server sends matching query and MAC).");
		    		escritor.println("OK");
				}
				else
				{
					escritor.println("ERROR");
					exito = false;
				}
				
			}
			else
			{
				escritor.println("ERROR");
				exito = false;
			}
			
			
			escritor.close();
			lector.close();
			
		}
		catch (Exception e) 
		{ 
			e.printStackTrace(); 
		}
		
		
		try {
			if (exito)
		        System.out.println(dlg + "Finishing test: passed.");		
		    else
		       	System.out.println(dlg + "Finishing test: failed.");
		        
			sc.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	
	//Metodos
	
	//Metodo que retorna el valor de string convertido en bytes
	public byte[] str2byte( String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
	//Metodo que retorna G^X, o en caso de cliente G^Y
	private BigInteger G2Y(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente,modulo);
	}
	
	//Metodo que calcula la llave maestra G^x^y
	private BigInteger calcular_llave_maestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente, modulo);
	}
	
	//Metodo que convierte de byte a string
	public String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}
	
	//Genera los IvBytes
	private byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}
	
