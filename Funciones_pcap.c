
/*
-----------------------------------
Ut desint vires, tamen est laudanda voluntas.
-------------------------------------
    Funciones_pcap.c
 ------------------------------------
En este programa se explica el
funcionamiento general de varias funciones
de la librería libpcap.
El programa fue realizado en una plataforma
LINUX Ubuntu 20.04.4 LTS.
Bajo el standard ANSI-C.

Para compilar este programa
utilizar el siquiente comando 
bajo una consola Linux, con las
librerías libpcap cargadas
en el sistema operativo.
Compilar:

$ gcc -Wall -Werror -o Funciones_pcap  Funciones_pcap.c -lpcap

Para ejecutar el programa:

./Funciones_pcap
------------------------------------
Hilario Iglesias Martínez.
-------------------------------------

*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main()
{
  
  char *IP; /* notación de punto de la dirección IP de red */
  char *Mascara;/* notación de punto de la dirección de la mascara de red*/
  int Retorno_Look;   /*Retorno del código de la llamada pcap_lookupnet */
  char errbuf[PCAP_ERRBUF_SIZE];/*Bufer para devolver los errores*/
  bpf_u_int32 IP_RAW; /* Valor IP bruta-Kernel */
  bpf_u_int32 Mascara_RAW;/* Mascara de red bruta-kernel */
  struct in_addr Direccion_Addr;/*Asociacion de llamada
                                  a la struct in_addr*/
  pcap_if_t *Dispositivo ;

  /*
pcap_if *   next
  si no es NULL, un puntero al siguiente
  elemento de la lista;siendo NULL para
  el último elemento de la lista
  ------
char *  name. un puntero a una cadena
que da un nombre para que el dispositivo pase a pcap_open_live()
  ----------
char *  description
  si no es NULL, un puntero a una cadena
  que proporciona una descripción legible
  por humanos del dispositivo
  -------------
pcap_addr * addresses
  un puntero al primer elemento de una
  lista de direcciones para la interfaz
  -------------
u_int   flags
 Indicadores de interfaz PCAP_IF_. Actualmente,
 el único indicador posible es PCAP_IF_LOOPBACK,
 que se establece si la interfaz es una
 interfaz de bucle invertido.
---------------------
  */

  /*
  Estructura Tipo in_addr Direccion_Addr
  ----------------- 
 situada en: include <netinet/in.h>

struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};
Estructura anidada.
struct in_addr {
    unsigned long s_addr;   abierta con inet_aton()
};

  */

  /* Llamamos a la función pcap_findalldevs()
  para elegir el primer dispositivo válido del equipo */

  
    if(pcap_findalldevs(&Dispositivo, errbuf) == 0) {
       
            printf("%s \n", Dispositivo->name);
            
        }
        
    else {
        printf("error: %s\n", errbuf);
        exit(-1);
    }
   
  
  /* Llamada a pcap_lookupnet(), para asociadar el dispositivo o tarjeta
  de red, con la dirección IP y la máscara de red */
  Retorno_Look = pcap_lookupnet(Dispositivo->name,&IP_RAW,&Mascara_RAW,errbuf);

  if(Retorno_Look == -1)
  {
   printf("%s\n",errbuf);
   exit(1);
  }

  /* Procedemos a optener en formato legible la dirección Ip
  y la máscara de red mediante la función  
  inet_aton(),que convierte la dirección de host de Internet 
  de la notación de números y puntos IPv4 en forma binaria
  (en orden de bytes de red) y la almacena en la estructura
  a la que apunta un puntero.
  inet_aton() devuelve un valor distinto de cero
  si la dirección es válida, cero si no lo es.
  La dirección suministrada en el resultado
  será válida e inteligible como salida por consola.

  */
  Direccion_Addr.s_addr = IP_RAW;
  IP = inet_ntoa(Direccion_Addr);

  if(IP == NULL)
  {
    perror("inet_ntoa");
    exit(1);
  }
/*imprimimos IP*/
  printf("Dirección IP: %s\n",IP);

  /* Hacemos lo mismo  para la máscara de red */
  Direccion_Addr.s_addr = Mascara_RAW;
  Mascara = inet_ntoa(Direccion_Addr);
  
  if(Mascara == NULL)
  {
    perror("inet_ntoa");
    exit(1);
  }
  /*Imprimimos máscara de red*/
  printf("Máscara de Red: %s\n",Mascara);

  return 0;
}
