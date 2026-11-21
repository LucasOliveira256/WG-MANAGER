# WG Manager: implantação na RouterBoard

Painel web leve para criar e gerenciar peers WireGuard em uma MikroTik com RouterOS v7 (container, ARM e ARM64). Go estático, frontend em HTML/CSS/JS puros embutido no binário, sem dependências externas em tempo de execução. Dados em `/data/config.json` (0600).

Funções: wizard de primeira configuração, login com senha única, criação de peers (chaves geradas no servidor, IP automático ou manual, preshared key opcional), geração e download do `.conf`, listagem com handshake e tráfego, ativar/desativar e remover.

## Endereçamento

Rede dos contêineres `10.133.133.0/24`, com um /30 por serviço. Valores de exemplo; ajuste à sua rede.

| Item | Valor |
|---|---|
| /30 do WG Manager | `10.133.133.0/30` |
| RB (gateway e REST API) | `10.133.133.1` |
| Container (painel) | `10.133.133.2`, porta `5555` |
| LAN | `192.168.10.0/24` |
| Sub-rede dos peers | `10.8.0.0/24` |

O painel é acessado direto em `http://10.133.133.2:5555`, por roteamento, sem NAT.

## 1. Gerar as imagens

Requisitos no PC de build: Docker com buildx, Python 3 e internet (o Go roda dentro da imagem).

O visual segue o tema EDGE (Chakra Petch, Inter e JetBrains Mono, embutidas no binário para funcionar offline). A Inter já acompanha o projeto; baixe as outras duas uma vez, antes do build:

```sh
python3 scripts/fetch-fonts.py
```

Sem esse passo o painel funciona normalmente, apenas com fontes de reserva do sistema nos títulos e nos dados.

```sh
sudo docker buildx create --name wgm --driver docker-container --use
sudo docker buildx inspect --bootstrap

sudo docker buildx build --platform linux/arm64  -t wg-manager:arm64 -o type=docker,dest=wg-manager-arm64.tar .
sudo docker buildx build --platform linux/arm/v7 -t wg-manager:armv7 -o type=docker,dest=wg-manager-armv7.tar .
```

Veja a arquitetura da RB em `/system resource print` (`arm64` ou `arm`) e envie o `.tar` correspondente para a RB (Files).

## 2. Configurar o RouterOS

**Modo container** (pacote `container` instalado; confirme fisicamente com o botão de reset/mode ou religando a energia):

```routeros
/system/device-mode/update container=yes
```

**REST API**, liberada só para o container:

```routeros
/ip service set www disabled=no port=80 address=10.133.133.2/32
```

Para HTTPS, use `www-ssl` (porta 443, certificado autoassinado) e marque "Usar HTTPS" no wizard.

**Usuário dedicado:**

```routeros
/user group add name=wgm-api policy=read,write,rest-api,sensitive
/user add name=wgm group=wgm-api address=10.133.133.2/32 password="DEFINA-UMA-SENHA-FORTE"
```

A policy `sensitive` é necessária para a REST API ler `/interface/wireguard`. Ela permite ler chaves e senhas na RB, por isso use senha forte e mantenha o `address=` restrito ao container.

**Rede do container:**

```routeros
/interface bridge add name=br-wgm
/ip address add address=10.133.133.1/30 interface=br-wgm
/interface veth add name=veth-wgm address=10.133.133.2/30 gateway=10.133.133.1
/interface bridge port add bridge=br-wgm interface=veth-wgm
```

**Firewall do painel.** As regras usam uma interface list `LAN`; se ela não existir: `/interface list add name=LAN` e `/interface list member add list=LAN interface=<sua-bridge-lan>`.

```routeros
/ip firewall filter add chain=input action=accept src-address=10.133.133.2 dst-address=10.133.133.1 protocol=tcp dst-port=80 place-before=0 comment="wgm: container -> REST API"
/ip firewall filter add chain=forward action=drop dst-address=10.133.133.2 protocol=tcp dst-port=5555 in-interface-list=!LAN place-before=0 comment="wgm: painel apenas LAN"
```

**Volume e container** (use `wg-manager-arm64.tar` em ARM64):

```routeros
/container mounts add list=wgm-mounts src=/wgm-data dst=/data
/container envs add list=wgm-env key=PORT value=5555
/container add file=wg-manager-armv7.tar interface=veth-wgm root-dir=wgm-root mountlists=wgm-mounts envlists=wgm-env name=wg-manager start-on-boot=yes logging=yes
/container start wg-manager
```

Em RB com disco, prefixe os caminhos (`/disk1/wgm-data`, `root-dir=disk1/wgm-root`).

## 3. Primeiro acesso

Abra `http://10.133.133.2:5555` e siga o wizard:

1. Senha da página (mínimo 8 caracteres).
2. RouterBoard: host `10.133.133.1`, porta `80`, usuário `wgm` e a senha criada. **Testar conexão** habilita o avanço.
3. Servidor WireGuard: criar uma interface nova (nome, listen-port, sub-rede, IP do servidor, endpoint público, DNS e AllowedIPs dos clientes) ou adotar uma existente.
4. Cole na RB os comandos mostrados no final: a regra de entrada da porta UDP do WireGuard e o NAT dos peers.

O NAT dos peers é necessário para os clientes navegarem pela VPN (AllowedIPs com `0.0.0.0/0`):

```routeros
/ip firewall nat add chain=srcnat action=masquerade src-address=10.8.0.0/24 comment="wg-manager: internet para os peers"
```

Se quiser, restrinja com `out-interface=` ou `out-interface-list=` da sua WAN.

## Segurança

- A senha da RB fica em `/data/config.json` (0600), pois o sistema precisa dela para chamar a API.
- Chaves privadas dos peers nunca são gravadas nem registradas em log: aparecem uma única vez, na criação.
- Login por cookie HttpOnly/SameSite=Strict, token CSRF em todo POST e limite de tentativas por IP. As sessões ficam em memória e são perdidas ao reiniciar o container.
- O painel usa HTTP simples na LAN. O sistema não altera o firewall: os comandos são apenas exibidos.
- Para refazer o wizard, apague `config.json` do volume.
