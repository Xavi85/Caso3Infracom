package seguridad;

import java.io.BufferedReader;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClienteMain {

	public static final int PUERTO = 4030;
	public static final String SERVIDOR = "localhost";
	
	public static void main(String args[]) throws IOException {
		
		Socket sc = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		int idCliente = 0;
		
		System.out.println("Inicialización cliente ...");
		
		try 
		{
			System.out.println("Creando conexion con servidor...");
			sc = new Socket(SERVIDOR, PUERTO);
			
			//Crea la comunicacion entre el servidor y el cliente 
			escritor = new PrintWriter(sc.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(sc.getInputStream()));
			
			System.out.println("Conexión establecida");
			
			//Crea un flujo para leer lo que escribe el cliente por teclado
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			
			//Inicializa el thread de cliente
			ClienteThread cliente = new ClienteThread(stdIn, lector, escritor, idCliente);
			cliente.start();
			idCliente++;
			
			
			stdIn.close();
			escritor.close();
			lector.close();
			sc.close();
			
		}
		catch (IOException e) 
		{
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}
		
		
		
		
		
		
		
		
	}
}
