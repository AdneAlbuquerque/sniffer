import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys


def menuPrincipal():
    print('''\nSeleccione uma opçao:
    1. Analisar pacotes de um protocolo específico
    2. Analizar todos os pacotes de calquer protocolo
    3. Sair
    ''')
    return


def inputNomeInterface():
    nombreInterfaz = input('Nome da interface de Rede: ')
    choice = input('A rede "{}" será analisada '.format(nombreInterfaz))
    return nombreInterfaz


def numValido(message):
    while True:
        try:
            val = int(input(message))
            if val <= 0:
                print('Formato incorreto')
            else:
                return val
        except ValueError:
            print('Não é uma opção válida\n')


def resumProtocolPacket(interface, numPaquete, protocolo):
    try:
        a = sniff(filter=protocolo, count=numPaquete, iface=nombreInterfaz, prn=lambda x: x.summary())
        print(a)
        return
    except:
        sys.exit('Ocorreu um erro. Verifique se o protocolo é compatível com sua interface de rede.\n')


def infoProtocolPacket(interface, numPaquete, protocolo):
    try:
        a = sniff(filter=protocolo, count=numPaquete, iface=nombreInterfaz, prn=lambda x: x.show())
        print(a)
        return
    except:
        sys.exit('A interface não foi encontrada, certifique-se de ter digitado o nome corretamente.\n')


def resumPacket(interface, numPaquete):
    try:
        a = sniff(count=numPaquete, iface=nombreInterfaz, prn=lambda x: x.summary())
        print(a)
        return
    except:
        sys.exit('A interface não foi encontrada, certifique-se de ter digitado o nome corretamente.\n')


def infoPacket(interface, numPaquete):
    try:
        a = sniff(count=numPaquete, iface=nombreInterfaz, prn=lambda x: x.show())
        print(a)
        return
    except:
        sys.exit('A interface não foi encontrada, certifique-se de ter digitado o nome corretamente.\n')


def protocolPackets():
    while True:
        print('''\nProtocolos aceitos:
        Ethernet (éter)
        LAN sem fio (wlan)
        Protocolo de internet (ip)
        IPv6 (ip6)
        Protocolo de resolução de endereço (arp)
        ARP reverso (rarp)
        Protocolo de controle de transmissão (tcp)
        Protocolo de datagrama do usuário (udp)
        Protocolo de mensagens de controle da Internet (icmp)
        ''')

        protocolo = input('Digite o protocolo que deseja filtrar:')

        if protocolo not in {'ether', 'wlan', 'ip', 'ip6', 'arp', 'rarp', 'tcp', 'udp', 'icmp'}:
            print('Protocolo inválido\n')
            continue
        else:
            choice = input('\nQuer ver todas as informações sobre cada pacote? (S/N): ')

            if choice in {'S'}:
                choice = input('\nSerão analisados 50 pacotes, deseja alterar esse número? (S/N): ')
                if choice in {'S'}:
                    numPaquete = numValido('Digite o número de pacotes que deseja analisar:: ')
                    infoProtocolPacket(nombreInterfaz, numPaquete, protocolo)
                else:
                    numPaquete = 50
                    infoProtocolPacket(nombreInterfaz, numPaquete, protocolo)
                break

            elif choice in {'N'}:
                choice = input('\nSerão analisados 50 pacotes, deseja alterar esse número? (S/N): ')
                if choice in {'S'}:
                    numPaquete = numValido('Digite o número de pacotes que deseja analisar:: ')
                    resumProtocolPacket(nombreInterfaz, numPaquete, protocolo)
                else:
                    numPaquete = 50
                    resumProtocolPacket(nombreInterfaz, numPaquete, protocolo)
                break

            else:
                print('Invalid option\n')


def analizarPacotes():
    while True:
        choice = input('\nQuer ver todas as informações sobre cada pacote? (S/N): ')

        if choice in {'S'}:
            choice = input('\nSerão analisados 50 pacotes, deseja alterar esse número? (S/N): ')
            if choice in {'S'}:
                numPaquete = numValido('Insira o número de pacotes que deseja analisar: ')
                infoPacket(nombreInterfaz, numPaquete)
            else:
                numPaquete = 50
                infoPacket(nombreInterfaz, numPaquete)
            break

        elif choice in {'N'}:
            choice = input('\nSerão analisados 50 pacotes, deseja alterar esse número? (S/N): ')
            if choice in {'S'}:
                numPaquete = numValido('Insira o número de pacotes que deseja analisar: ')
                resumPacket(nombreInterfaz, numPaquete)
            else:
                numPaquete = 50
                resumPacket(nombreInterfaz, numPaquete)
            break

        else:
            print('Opção  inválida\n')


def loopMenu():
    while True:

        menuPrincipal()

        choice = int(input('Escolha uma opção: '))

        if choice == 1:
            protocolPackets()


        elif choice == 2:
            analizarPacotes()


        elif choice == 3:

            sys.exit()

        else:
            print('Opção  inválida \n')


if __name__ == '__main__':
    print('---Sniffer De Rede---\n')

    nombreInterfaz = inputNomeInterface()

    loopMenu()