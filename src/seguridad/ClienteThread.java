package seguridad;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ClienteThread extends Thread{

	//Constantes
	
	
	//Atributos
	private PrintWriter escritor = null;
	private BufferedReader lector = null;
	private int idCliente = -1;
	private BufferedReader stdIn = null;
	private SecurityFunctions f;
	private String dlg;
	private BigInteger p;
	private BigInteger g;
	
	
	//Metodo constructor 
	//Recibe el lector de lo que escribe el cliente, de lo que devuelve el servidor, escritor de lo que
	//envia al servidor, y el id de cliente.
	public ClienteThread (BufferedReader pStdIn, BufferedReader pLector, PrintWriter pEscritor, int pIdCliente)
	{
		stdIn = pStdIn;
		lector = pLector;
		escritor = pEscritor;
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
			String msj = g.toString()+","+p.toString()+","+linea;
			
			//Luego tiene que recibir la firma 
			linea = lector.readLine();
			byte[] byteauthentication = linea.getBytes();
			
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
	    		escritor.println("str_valor_comun");
	    		
	    		//Calculamos la llave maestra
	    		// computing (G^x)^y mod N
	    		BigInteger llave_maestra = calcular_llave_maestra(g2x,biy,p);
	    		String str_llave = llave_maestra.toString();
	    		System.out.println(dlg + " llave maestra: " + str_llave);
				
	    		//A partir de la llave maestra se calcula la llave simetrica de cifrado y HMAC
	    		SecretKey sk_srv = f.csk1(str_llave);
				SecretKey sk_mac = f.csk2(str_llave);
				
				//De igual manera, se calcula iv_1
				byte[] iv1 = generateIvBytes();
	        	String str_iv1 = byte2str(iv1);
				IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);
				
				
				//Enviar un mensaje cifrado
				
				//Primero el cliente ingresa un numero 
				System.out.println("Ingrese un numero: ");
				linea = stdIn.readLine();
				
				try
				{
					
				}
				
				
				
				
			}
			else
			{
				escritor.println("ERROR");
				exito = false;
			}
			
			
			
			
			
			
			
			
			
		}
		catch (Exception e) 
		{ 
			e.printStackTrace(); 
		}
		
	}
	
	
	//Metodos
	
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
	
	
	
	
	
	
	
	
	
	
}
