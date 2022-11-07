package seguridad;

import java.io.BufferedReader;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class ClienteMain {

	public static final int PUERTO = 4030;
	public static final String SERVIDOR = "localhost";
	
	public static void main(String args[]) throws IOException {
		
		Socket sc = null;
		int idCliente = 0;
		
		System.out.println("Inicialización cliente ...");
		
		try 
		{
			
			Scanner lecturaConsola = new Scanner(System.in);
			System.out.println("Ingrese numero de clientes a correr:");
			int numClientes = lecturaConsola.nextInt();
			lecturaConsola.close();
			
			for(int i=0; i<numClientes; i++) {
				System.out.println("Creando conexion con servidor...");
				sc = new Socket(SERVIDOR, PUERTO);
				
				System.out.println("Conexión establecida");
				
				//Inicializa el thread de cliente
				ClienteThread cliente = new ClienteThread(sc, idCliente);
				cliente.start();
				idCliente++;
			}
			
			
			
			
			
		}
		catch (IOException e) 
		{
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}
