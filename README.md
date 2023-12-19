# Iptables-secure

<p align="center">
<img src="Logotipo.png">
</p>

iptables es una herramienta de firewall para sistemas Linux. Su nombre proviene de "Internet Protocol Tables" y se utiliza para configurar y gestionar las reglas de filtrado de paquetes en el kernel de Linux. iptables es una parte esencial de la seguridad de red en sistemas basados en Linux y se utiliza para controlar el tráfico de red entrante y saliente en un servidor o una computadora.

Aquí hay algunas de las cosas para las que se utiliza iptables:

**Firewall:** iptables se utiliza principalmente como un firewall para proteger una red o una computadora contra amenazas de seguridad. Puedes definir reglas para permitir o bloquear paquetes en función de diversas condiciones, como la dirección IP de origen o destino, el puerto, el protocolo, etc. Esto te permite controlar qué tipo de tráfico se permite o se deniega.

**NAT:** (Network Address Translation): iptables se usa comúnmente para configurar la traducción de direcciones de red. Esto es útil cuando tienes múltiples dispositivos en una red privada y deseas permitir que todos ellos compartan una única dirección IP pública. NAT se utiliza enrutando el tráfico desde y hacia dispositivos en una red interna a través de una dirección IP pública.

Este script te servirá para configurar Iptables de manera fácil y rápida para mantener tu servidor seguro.

```
git clone https://github.com/Devsebastian31/Iptables-secure.git

cd Iptables-secure

sudo python3 Iptables.py
```

<p align="center">
<img src="./Img/Iptables.png">
</p>
