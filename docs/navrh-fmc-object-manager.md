# Navrh webove aplikace FMC Object Manager

## Cile aplikace

Aplikace bude slouzit jako interni webovy nastroj pro spravu objektu v Cisco FMC na adrese `https://10.62.8.190/`.
Primarni pouziti je bezpecna prace s objekty, jejich validace, audit zmen a sprava hodnot override pro konkretni zarizeni.

Pozadovana cilova verze prostredi je FMC `10.0.1`. Protoze konkretni dostupnost REST API endpointu se muze lisit podle instalace, licence a zapnutych funkci, aplikace musi pri prvnim pripojeni nacist schopnosti FMC a overit podporovane operace proti realne instanci.

## Zakladni architektura

```text
Browser
  React / TypeScript UI
        |
        v
Backend API
  FastAPI nebo NestJS
  lokalni autentizace a RBAC
  FMC adapter
  validace a diff engine
  audit log
        |
        v
PostgreSQL
  lokalni uzivatele, role, audit, drafty, cache metadat
        |
        v
Cisco FMC REST API
  https://10.62.8.190
```

Browser nikdy nebude komunikovat primo s FMC. FMC tokeny, prihlasovaci udaje a TLS nastaveni zustanou pouze na backendu.

## Lokalni sprava uzivatelu

Aplikace nebude pouzivat externi identitu, LDAP, SAML ani OIDC. Uzivatele budou spravovani lokalne v databazi aplikace.

### Funkce

- Vytvoreni prvniho administratora pri inicializaci aplikace.
- Sprava uzivatelu pouze pro roli `admin`.
- Aktivace, deaktivace a zamykani uctu.
- Reset hesla administratorem.
- Povinna zmena hesla pri prvnim prihlaseni nebo po resetu.
- Volitelne TOTP MFA pro administratorske ucty.
- Session management s moznosti odhlasit vsechny relace uzivatele.
- Audit prihlaseni, neuspesnych prihlaseni a administrativnich zmen.

### Hesla a relace

- Hesla ukladat pouze jako hash `argon2id`.
- Vynucena minimalni delka hesla, napriklad 14 znaku.
- Rate limiting prihlaseni podle uzivatele a IP adresy.
- Kratkodobe access session cookies s `HttpOnly`, `Secure` a `SameSite=Strict`.
- Server-side session store nebo podepsane session tokeny s moznosti okamzite revokace.

### Role

Doporucene lokalni role:

| Role | Opravneni |
| --- | --- |
| `viewer` | Cteni objektu, override, referenci, historie a deployment stavu. |
| `operator` | Vytvareni draftu zmen a spousteni validaci. |
| `approver` | Schvaleni a aplikace pripravenych zmen do FMC. |
| `admin` | Sprava uzivatelu, nastaveni FMC konektoru, role, systemove nastaveni. |

Role aplikace jsou nezavisle na FMC uctech. Do FMC se backend pripojuje pres dedikovany FMC service account.

## FMC konektor

Backend bude mit izolovanou vrstvu `FmcClient`, ktera resi:

- prihlaseni do FMC a obnovu tokenu,
- ulozeni FMC tokenu pouze v pameti nebo sifrovanem cache store,
- praci s domenami,
- strankovani,
- retry logiku,
- jednotne zpracovani FMC chyb,
- TLS overeni certifikatu,
- mapovani FMC odpovedi na interni datove typy.

### Konfigurace FMC

Konfigurace bude ulozena lokalne a dostupna jen administratorum:

- FMC base URL: `https://10.62.8.190`
- FMC username service accountu
- FMC password ulozeny sifrovane
- TLS CA certificate nebo rezim lab-only pro self-signed certifikat
- vybrana defaultni domena
- timeouty a limity strankovani

## Podporovane objekty

Prvni verze by mela podporovat tyto kategorie:

- host objects,
- network objects,
- range objects,
- FQDN objects,
- network groups,
- port objects,
- port groups,
- protocol / ICMP objekty.

Kazdy typ objektu bude mit vlastni schema validace. UI nesmi posilat do FMC volne JSON editory jako primarni cestu; JSON rezim muze byt dostupny jen jako admin/debug nastroj.

## Override objektu

Override musi byt modelovany jako prvotridni funkce, ne jako poznamka u objektu.

### UI model

Detail objektu bude mit zalozky:

- `Global`
- `Overrides`
- `Usage`
- `History`

Zalozka `Overrides` zobrazi:

- zda objekt podporuje override,
- globalni hodnotu,
- seznam zarizeni s aktivnim override,
- konkretni override hodnotu,
- rozdil oproti globalni hodnote,
- stav posledni synchronizace s FMC.

### Operace

Aplikace musi podporovat:

- vytvoreni override pro zarizeni,
- upravu existujiciho override,
- odstraneni override a navrat na globalni hodnotu,
- hromadne zobrazeni override pres vice zarizeni,
- validaci, ze override hodnota odpovida typu objektu,
- audit kazde override zmeny.

### Interni datovy model

```text
fmc_objects
  id
  domain_id
  fmc_id
  object_type
  name
  global_value
  raw_fmc_payload
  last_seen_at

fmc_object_overrides
  id
  object_id
  device_id
  override_value
  raw_fmc_payload
  last_seen_at

change_requests
  id
  requested_by
  approved_by
  status
  target_type
  target_id
  before_value
  after_value
  fmc_response
  created_at
  applied_at
```

## Change workflow

Zmeny nebudou zapisovane okamzite bez kontroly.

1. Uzivatel vytvori draft zmeny.
2. Backend nacte aktualni stav objektu z FMC.
3. Aplikace pripravi diff.
4. Validacni vrstva overi syntaxi, duplicity, kolize a podporu override.
5. Operator odesle zmenu ke schvaleni nebo ji aplikuje, pokud ma dostatecnou roli.
6. Backend zapise zmenu do FMC.
7. Vysledek se ulozi do audit logu.
8. Aplikace zobrazi, zda je potreba deployment na zarizeni.

## Audit

Audit log musi byt append-only z pohledu aplikacni logiky. Ukladat se bude:

- uzivatel aplikace,
- cas,
- IP adresa,
- typ operace,
- cilovy FMC objekt,
- predchozi hodnota,
- nova hodnota,
- FMC request metadata,
- FMC response metadata,
- vysledek operace.

Citliva data jako hesla, tokeny a session hodnoty se do auditu nikdy neukladaji.

## Obrazovky aplikace

### Dashboard

- stav spojeni s FMC,
- aktualni domena,
- pocet objektu,
- pocet objektu s override,
- posledni zmeny,
- cekajici schvaleni.

### Objects

- tabulkove zobrazeni objektu,
- filtr podle typu,
- vyhledavani podle nazvu, hodnoty a ID,
- oznaceni objektu s override,
- rychly pristup na detail.

### Object Detail

- globalni hodnota,
- override hodnoty,
- pouziti v policy,
- historie zmen,
- akce `Edit`, `Create override`, `Remove override`.

### Change Requests

- seznam draftu,
- schvalovani,
- diff,
- aplikace zmeny do FMC,
- vysledek FMC volani.

### Users

- lokalni uzivatele,
- role,
- stav uctu,
- reset hesla,
- revokace relaci,
- MFA stav.

### Settings

- FMC pripojeni,
- TLS nastaveni,
- defaultni domena,
- synchronizace,
- backup konfigurace aplikace.

## Bezpecnostni rozhodnuti

- FMC credentials nebudou dostupne ve frontend kodu.
- Pro zapis do FMC se pouzije service account s minimalnimi potrebnymi pravy.
- Kazda aplikacni akce bude kontrolovana pres lokalni RBAC.
- Produkcni provoz musi overovat TLS certifikat FMC.
- Lab-only rezim pro self-signed certifikat musi byt jasne oznaceny v UI.
- Exporty nesmi obsahovat tokeny ani hesla.
- Admin akce nad uzivateli budou auditovane stejne jako zmeny FMC objektu.

## Doporuceny implementacni postup

1. Zalozit backend API, databazi a lokalni prihlaseni.
2. Pridat FMC konektor a test spojeni s `https://10.62.8.190`.
3. Implementovat read-only nacitani domen a objektu.
4. Pridat cache objektu a zakladni UI tabulku.
5. Pridat detail objektu a zobrazeni override.
6. Implementovat draft/diff workflow.
7. Povolit zapis globalnich objektu.
8. Povolit zapis override.
9. Pridat schvalovani, audit a exporty.
10. Dodelat deployment status a provozni monitoring.

## Otevrene body k overeni proti FMC

- Potvrdit presnou software verzi primo z FMC API nebo UI.
- Overit dostupne REST API endpointy pro objektove override ve vasi instanci.
- Overit, zda vsechny pozadovane typy objektu podporuji override.
- Rozhodnout, zda zmeny muze aplikovat `operator`, nebo vzdy jen `approver`.
- Rozhodnout, zda ma aplikace deployment pouze indikovat, nebo take spoustet.
