# FMC Object Manager

Lokalni webova aplikace pro spravu objektu v Cisco FMC, vcetne lokalnich uzivatelu, RBAC, auditu a evidence object override.

## Spusteni

```bash
python3 app.py
```

Aplikace bezi na:

```text
http://127.0.0.1:8080
```

Pri prvnim startu se vytvori bootstrap administrator:

```text
username: admin
password: ChangeMe12345!
```

Heslo je po prvnim prihlaseni nutne zmenit. Pokud chcete nastavit jine prvni heslo, spustte aplikaci pred prvnim vytvorenim databaze takto:

```bash
FMC_APP_ADMIN_PASSWORD='nejake-dlouhe-bezpecne-heslo' python3 app.py
```

## Co je implementovano

- Lokalni uzivatele bez externi identity.
- Role `viewer`, `operator`, `approver`, `admin`.
- Session cookies a lokalni audit log.
- CRUD objektu v lokalni cache.
- Volitelny zapis novych/upravenych objektu do FMC vcetne pole `overridable`.
- Mazani objektu z aplikace; pokud ma objekt `fmc_id` a konektor je nastaveny, maze se i ve FMC.
- Razeni tabulky objektu podle sloupcu.
- Evidence override hodnot pro konkretni managed firewall target vcetne description.
- Change request workflow s lokalnim apply krokem.
- FMC nastaveni pro `https://10.62.8.190`.
- FMC REST API test prihlaseni pres `/api/fmc_platform/v1/auth/generatetoken`.
- Import Host objektu z FMC pres REST API, pokud je konektor spravne nastaveny.

## Poznamky k FMC

Backend drzi FMC service account a tokeny mimo browser. Object override zapisuje pres FMC object endpoint daneho typu: vytvoreni pres `POST /api/fmc_config/v1/domain/{domain_UUID}/object/{endpoint}` s payloadem `overrides.parent` a `overrides.target`, upravu pres `PUT /object/{endpoint}/{parentObjectId}?overrideTargetId={targetId}` a mazani override hodnoty pres `DELETE /object/{endpoint}/{parentObjectId}?overrideTargetId={targetId}`.

Pri vytvareni nebo uprave objektu je ve formulari volba `Povolit override ve FMC`. Pokud je zaroven zapnute `Zapsat do FMC` a FMC konektor je nastaveny, aplikace posle do FMC objekt s `overridable: true`. U starsich lokalnich objektu bez `fmc_id` staci objekt otevrit, nechat zapnuty zapis do FMC a ulozit; aplikace ho vytvori ve FMC a propoji lokalni cache s FMC ID.

Override editor nacita managed firewally z FMC endpointu `/devices/devicerecords`. Po vyberu target FW ukaze puvodni hodnotu objektu a predvyplni editovatelnou override hodnotu, kterou lze upravit. Soucasti override je i editovatelne pole `Description`.

Pokud objekt nebo jeho override zmenite primo ve FMC, pouzijte v detailu objektu `Refresh z FMC`. Aplikace znovu nacte globalni hodnotu objektu a dostupne FMC override polozky pres endpoint `/{objectType}/{objectId}/overrides`. Lokalne zadane override polozky pri refreshi nemaze. Drive zobrazene tlacitko `Nacist z FMC` delalo stejnou vec a bylo odstraneno, aby UI nemelo dve ruzna jmena pro jednu akci.

Tabulka override zobrazuje `Source` a `Last sync`. Hodnota `fmc` znamena, ze zaznam prisel z FMC nebo byl do FMC uspesne zapsan. Hodnota `local` znamena lokalni evidenci vytvorenou v aplikaci, typicky pro objekt bez `fmc_id` nebo bez nastaveneho FMC konektoru.

Pokud FMC pouziva self-signed certifikat a test spojeni vraci `CERTIFICATE_VERIFY_FAILED`, otevrene v aplikaci:

```text
Nastaveni > FMC pripojeni
```

Pro lab provoz vypnete `Overovat TLS certifikat`, ulozte nastaveni a zkuste `Test spojeni` znovu. Pro produkcni provoz je vhodnejsi pridat CA certifikat FMC do duveryhodnych certifikatu systemu, na kterem bezi aplikace.

## Data

Runtime data jsou ulozena v adresari `data/`:

- `data/app.db` - SQLite databaze.
- `data/app.secret` - lokalni aplikacni tajemstvi pro ulozeni FMC hesla.

Tyto soubory nejsou urcene ke commitovani.
