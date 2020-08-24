# Program popcl

## Popis

Program slouží ke stahování, popřípadě mazání elektronické pošty ze schránky přes protokol pop3 nebo pop3s.

## Rozšíření

Využívání metody UIDL pro označování zpráv, což vede ke značnému zrychlení programu při stahování nových zpráv ze schránky s velkým objemem zpráv. Pokud UIDL není k dispozici, využívá se k označování identifikátor vygenerovaný z obsahu zprávy.

## Použití

popcl \<server> [-p \<port>][-T|-S [-c \<certfile>][-C \<certaddr>]] [-d] [-n] -a \<auth_file> -o \<out_dir>

## Přepínače

### Povinné

**\<server>** Doménové jméno nebo IP adresa požadovaného zdroje. Uvádí se jako parametr bez přepínače. V případě zadání více parametrů bez přepínače, je zvolen první výskyt.

**-a** Vynucuje autentizaci uživatele. Konfiguračního souboru **\<auth_file>** obsahuje přihlašovací údaje ve tvaru:

username = jmeno

passoword = heslo

**-o** Specifikuje výstupní adresář **\<out_dir>**, do kterého program ukládá stažené zprávy.

### Volitelné

**-p \<port>** Určí explicitně komunikační port jinak je zvolen výchozí port registrovaný organizací IANA (110 nebo 955 v závislosti na parametru -T).

**-h** Vytiskne nápovědu k programu. Pokud je zadaný argument -h neprovádí se nic jiného než tisk nápovědy.

**-T** Zapíná šifrování celé komunikace.

**-S** Naváže nešifrovanou komunikaci se serverem a následně pomocí příkazu STLS přejde na šifrovanou variantu protokolu.

**-c \<certfile>** Definuje soubor **\<certfile>** s certifikáty, který se použije pro ověření platnosti certifikátu SSL/TLS (použití pouze s -T nebo -S).

**-C \<certaddr>** Definuje adresář **\<certaddr>** s certifikáty, který se použije pro ověření platnosti certifikátu SSL/TLS (použití pouze s -T nebo -S).

**-d** Po stažení zpráv ze serveru vymaže obsah celé schránky.

**-n** Specifikuje, že se budou stahovat pouze nové zprávy.

## Příklady spuštění

	$ ./popcl pop3.seznam.cz -o maildir -a authfile

85 messages downloaded.

	$ ./popcl 10.10.10.1 -p 8466 -T -n -o maildir -a authfile

2 new messages downloaded.

	$ ./popcl pop3.seznam.cz -o maildir -a /dev/null

Login to server "pop3.seznam.cz" failed.

	$ ./popcl eva.fit.vutbr.cz -o maildir -a authfile -T -c /dev/null

Error: Certificates not found.

Identity of server "pop3.seznam.cz" can not be verified.

