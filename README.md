<p align="center">
  <img src="web/logo.png" alt="EDGE" width="200">
</p>

<h1 align="center">WG Manager</h1>

<p align="center">
  Painel web leve para criar e gerenciar peers WireGuard em uma MikroTik com RouterOS v7.<br>
  Roda como container na própria RouterBoard (ARM e ARM64).
</p>

---

## Por que existe

Criar um peer WireGuard no RouterOS à mão exige gerar chaves no cliente, escolher um IP livre, cadastrar o peer na RB e montar o arquivo `.conf` sem errar nenhum campo. O WG Manager faz isso em um formulário: gera as chaves, aloca o IP conferindo o que já está em uso na RB, cria o peer e entrega o `.conf` pronto para o cliente.

<!-- Adicione capturas de tela em docs/screenshots/ e referencie aqui. -->

## Recursos

- **Wizard de primeira configuração:** senha do painel, conexão com a RB (com "Testar conexão"), criação de uma interface WireGuard nova ou adoção de uma existente, e exibição das regras de firewall e NAT para você colar na RB.
- **Criação de peers:** par de chaves Curve25519 gerado no backend, preshared key opcional, IP automático (próximo livre) ou manual validado contra os peers, os endereços da RB e a sub-rede.
- **Arquivo `.conf`:** download e cópia do texto. A chave privada aparece uma única vez e nunca é gravada no servidor.
- **Lista de peers:** nome, IP, estado, último handshake e tráfego, com ações de ativar, desativar e remover.
- **Acesso protegido:** senha única com hash bcrypt, cookie `HttpOnly` e `SameSite=Strict`, token CSRF em todo POST e limite de tentativas de login por IP.

## Como funciona

```
Navegador  ──HTTP──►  WG Manager (container)  ──REST /rest──►  RouterOS
 (LAN)                 Go + frontend embutido                  /interface/wireguard
                       /data/config.json                       /interface/wireguard/peers
                                                               /ip/address
```

O WG Manager não guarda peers. A fonte da verdade é a RouterBoard: cada ação consulta ou altera a RB pela REST API. O único estado local é o `config.json` com a senha (hash), os dados de acesso à RB e os padrões do servidor WireGuard.

## Stack

| Parte | Escolha |
|---|---|
| Backend | Go, biblioteca padrão; única dependência externa: `golang.org/x/crypto` (bcrypt) |
| Frontend | HTML, CSS e JS puros, embutidos no binário com `go:embed` (sem frameworks e sem CDN) |
| Persistência | Arquivo JSON em `/data` (permissão 0600), sem banco externo |
| Imagem | Multi-stage, runtime `FROM scratch`, binário estático (`CGO_ENABLED=0`) |
| Tamanho | Imagem `armv7` de cerca de 2,6 MB; memória em uso de cerca de 1,6 MB no RouterOS (valores observados em uma RB ARM 32 bits) |

## Requisitos

- RouterBoard com RouterOS v7 (container exige 7.6 ou superior), pacote `container` instalado e modo container habilitado.
- Um usuário dedicado na RB para a REST API. O grupo precisa das policies `read`, `write`, `rest-api` e `sensitive`.
- No PC de build: Docker com buildx e, para as fontes do tema, Python 3. O Go não precisa estar instalado (a compilação roda dentro da imagem).

## Início rápido

```sh
# fontes do tema (Chakra Petch e JetBrains Mono), uma vez
python3 scripts/fetch-fonts.py

# builder com suporte a exportar .tar (uma vez)
sudo docker buildx create --name wgm --driver docker-container --use
sudo docker buildx inspect --bootstrap

# uma imagem por arquitetura, prontas para importar na RB
sudo docker buildx build --platform linux/arm64  -t wg-manager:arm64 -o type=docker,dest=wg-manager-arm64.tar .
sudo docker buildx build --platform linux/arm/v7 -t wg-manager:armv7 -o type=docker,dest=wg-manager-armv7.tar .
```

Envie o `.tar` da arquitetura da sua RB (`/system resource print`), configure o container e acesse o painel. Os comandos do RouterOS (REST API, usuário, rede do container, firewall, volume) estão em **[docs/IMPLANTACAO.md](docs/IMPLANTACAO.md)**.

## Configuração

| Variável | Padrão | Descrição |
|---|---|---|
| `PORT` | `5555` | Porta HTTP do painel |
| `DATA_DIR` | `/data` | Pasta do `config.json`; monte um volume aqui |

Todo o resto (RB, interface, sub-rede, endpoint, DNS e AllowedIPs dos clientes) é definido no wizard.

## Desenvolvimento

Requer Go 1.22 ou superior e uma RB acessível pela REST API.

```sh
go mod tidy
DATA_DIR=./data PORT=5555 go run .
```

Estrutura:

```
.
├── main.go          servidor HTTP, cabeçalhos de segurança, embed do frontend
├── handlers.go      rotas da API, wizard, login e gestão de peers
├── ros.go           cliente da REST API do RouterOS
├── wg.go            chaves Curve25519, IPs em uso, validações e geração do .conf
├── auth.go          sessões, CSRF e limite de tentativas de login
├── store.go         persistência em /data/config.json
├── web/             frontend (index.html, app.css, app.js, logos, fontes)
├── scripts/         fetch-fonts.py
├── docs/            guia de implantação na RouterBoard
└── Dockerfile
```

## Segurança

- A senha da RB fica em `/data/config.json` (0600), pois o sistema precisa dela para chamar a API. Proteja o volume e o acesso à RB.
- A policy `sensitive` do usuário da API permite ler chaves e senhas na RB. O sistema não usa isso, mas o usuário consegue. Use senha forte e restrinja o usuário e o serviço ao IP do container.
- Chaves privadas dos peers nunca são gravadas nem registradas em log.
- O painel serve HTTP simples e deve ficar acessível apenas pela LAN (veja as regras de firewall no guia de implantação). O cookie só recebe `Secure` quando o próprio container recebe TLS.
- As sessões ficam em memória e são perdidas ao reiniciar o container.
- O sistema não altera o firewall da RB: ele só mostra os comandos para você aplicar.

## Limitações

- Senha única, sem usuários separados.
- Não há QR code para os clientes móveis.
- Não há reconfiguração depois do wizard: para refazê-lo, apague `config.json` do volume.
- Gerencia os peers de uma interface WireGuard por instalação.
