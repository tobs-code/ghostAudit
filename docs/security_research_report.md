# Sicherheitsbericht: Manipulationssicheres Logging & Datenbank-Steganographie

Dieses Dokument fasst die Ergebnisse unserer umfassenden Recherche über professionelle, manipulationssichere Audit-Logging-Systeme und verdeckte Kanäle (Steganographie) in Datenbanken zusammen. Auf Basis dieser Best Practices der Industrie werden konkrete Vorschläge zur Verbesserung von **GhostAudit V7** (Orthogonal Grid Defense) erarbeitet.

---

## 1. Wie Profis Manipulationssicherheit (Tamper-Evidence) umsetzen

Klassische Audit-Logs in relationalen Datenbanken haben eine Schwachstelle: Sie sind änderbar. Administratoren oder Angreifer mit privilegiertem Zugriff (z. B. Root oder DBA) können Zeilen löschen, Werte modifizieren oder Logs deaktivieren. Professionelle Systeme setzen auf kryptografische Härtung, um jegliche nachträgliche Veränderung mathematisch nachweisbar zu machen.

### 1.1 Google Trillian (und Nachfolger Tessera)
*   **Technologie**: Merkle-Bäume (Merkle Hash Trees) in Go.
*   **Funktionsweise**:
    *   **Inclusion Proofs**: Beweisen in $O(\log n)$, dass ein spezifischer Log-Eintrag im Baum vorhanden ist, ohne den gesamten Baum herunterladen zu müssen.
    *   **Consistency Proofs**: Beweisen, dass der Log-Baum nur im Append-Only-Verfahren gewachsen ist und historische Daten nicht verändert oder umsortiert wurden.
    *   **Signed Tree Heads (STH)**: Der Root-Hash des Baums wird periodisch vom Betreiber kryptografisch signiert.
*   **Tessera**: Der Nachfolger (veröffentlicht Ende 2025) nutzt Tiled-APIs für extreme Skalierung und geringere Betriebskosten bei Cloud-Backends (S3/MySQL).

### 1.2 Sigstore / Rekor
*   **Technologie**: Ein transparenter, kryptografischer Ledger zur Absicherung von Software-Lieferketten.
*   **Zentrale Innovation**:
    *   **Witness Cosigning**: Unabhängige externe "Zeugen" (Witnesses) signieren die Root-Hashes des Logs. Dadurch wird verhindert, dass der Log-Betreiber unterschiedliche Sichten des Logs an verschiedene Clients ausliefert ("Split-View Attack").
    *   **rekor-monitor**: Kontinuierliche Überwachungstools verifizieren laufend die Append-Only-Konsistenz.

### 1.3 immudb (Immutable Database)
*   **Technologie**: Hochleistungsfähige, unveränderbare Datenbank mit gRPC-API.
*   **Funktionsweise**:
    *   Nutzt intern Merkle-Bäume.
    *   **Clientseitige Unabhängigkeit**: Der Client speichert den Root-Hash lokal und verifiziert bei jedem Zugriff selbst, ob der Server ehrlich arbeitet. Ein kompromittierter Datenbank-Admin kann Log-Einträge nicht unbemerkt manipulieren.

### 1.4 Amazon QLDB (Quantum Ledger Database)
*   **Technologie**: Zentralisierte Ledger-Datenbank.
*   **Funktionsweise**:
    *   Ein unveränderbares, physisches Append-Only-Journal zeichnet jede Transaktionshistorie auf.
    *   Die Transaktionen werden kryptografisch per SHA-256 verkettet (Hash-Chaining ähnlich einer Blockchain, aber ohne dezentralen Konsens overhead).

### 1.5 Akademische Standards (Schneier-Kelsey Modell)
*   **Prinzip**: Sicheres Logging auf ungesicherten Systemen.
*   **Kernidee**: **Vorwärtssicherheit (Forward Security)**.
    *   Der kryptografische Schlüssel zur Generierung von Signaturen/HMACs wird nach jedem Log-Eintrag mittels einer Einwegfunktion (z. B. $K_t = \text{Hash}(K_{t-1})$) weiterentwickelt.
    *   Der alte Schlüssel wird unwiderruflich gelöscht.
    *   Wenn ein Angreifer das System zum Zeitpunkt $t$ kompromittiert, besitzt er nur $K_t$. Er kann damit keine gefälschten Logs für Ereignisse vor dem Zeitpunkt $t$ erzeugen, da er $K_{t-1}$ mathematisch nicht rekonstruieren kann.

---

## 2. Steganographie & Covert Channels in Datenbanken

Während klassische Audit-Logs sichtbar sind, versteckt Steganographie die Existenz der Audit-Spur selbst. Datenbanken bieten durch ihre Struktur und Datentypen exzellente Verstecke (Carrier).

### 2.1 Least Significant Bit (LSB) in numerischen Feldern
*   **Prinzip**: Das niederwertigste Bit von Gleitkommazahlen (Floats) oder Integern wird manipuliert. Bei Floats betrifft dies die Mantisse.
*   **Vulnerability (Steganalyse)**: Einfaches Ersetzen des LSB erzeugt statistische Anomalien (z. B. unnatürliche Gleichverteilung von 0 und 1 bei den Endziffern).
*   **Gegenmaßnahme**: **LSB Matching (±1 Embedding)**. Wenn das Bit nicht übereinstimmt, wird der Wert stattdessen zufällig um +1 oder -1 der kleinsten Einheit verändert. Dies erhält das statistische Rauschen und erschwert die Entdeckung.

### 2.2 Whitespace-Kodierung (SNOW-Algorithmus)
*   **Prinzip**: Anfügen von unsichtbaren Leerzeichen (Spaces, Tabs) oder Unicode-Zeichen (z. B. Zero-Width Spaces `U+200B`) am Ende von Textfeldern.
*   **Problem**: Sehr fragil. Datenbank-Exporte, Textnormalisierung (z. B. `TRIM()`) oder App-Filter entfernen Whitespaces oft standardmäßig, was die verdeckten Bits zerstört.

### 2.3 Semantische Substitution (Synonyme)
*   **Prinzip**: Austausch von Wörtern durch Synonyme (z. B. "currently" ↔ "presently").
*   **Vorteil**: Extrem robust gegen Textnormalisierung und Konvertierung.
*   **Nachteil**: Erfordert ein Wörterbuch und kann den Schreibstil minimal verändern, was durch linguistische Analyse auffallen könnte.

### 2.4 Row-Ordering (Zeilenreihenfolge)
*   **Prinzip**: Die physische Speicherreihenfolge von Datensätzen in einer Tabelle wird als Covert Channel genutzt. Da relationale Datenbanken keine feste Reihenfolge garantieren (ohne `ORDER BY`), kann die Permutation der Zeilen (z. B. anhand von IDs) geheime Daten kodieren.
*   **Nachteil**: Sehr anfällig für Datenbank-Reorganisationen (wie `VACUUM` in SQLite oder Indizierungen).

### 2.5 Relationales Wasserzeichen (Agrawal-Kiernan Algorithmus)
*   **Standard (2002)**: Nutzt einen geheimen Schlüssel und die Primärschlüssel der Zeilen, um gezielt Pseudozufalls-Bits in ausgewählten Attributen zu modulieren. Wird primär für Urheberrechtsnachweise ("Traitor Tracing") genutzt, um Datenlecks zurückzuverfolgen.

---

## 3. Angriffe & Forensik (Anti-Forensics)

Angreifer, die Root- oder DBA-Rechte erlangen, versuchen, ihre Spuren zu verwischen. Ein Verständnis ihrer Methoden hilft bei der Härtung.

### 3.1 Angreifer-Techniken (Anti-Forensics)
1.  **Log-Deaktivierung**: Abschalten der Logging-Trigger oder Dienste vor dem Angriff.
2.  **OS-Level Editing**: Umgehen des DBMS. Der Angreifer editiert die raw SQLite-Datei (`.db`) mit einem Hex-Editor auf Betriebssystemebene, wodurch Datenbank-Trigger und Trigger-Beschränkungen komplett umgangen werden.
3.  **Timestomping**: Systemzeit manipulieren, um Ereignisse zeitlich falsch darzustellen.

### 3.2 Forensische Analyse-Methoden
1.  **Hash-Ketten-Validierung**: Prüfen, ob die kryptografische Kette gebrochen ist.
2.  **Snapshot-Reconciliation**: Vergleich des aktuellen Datenbankzustands mit Backups oder Transaktions-Logs (`WAL` / Write-Ahead Log).
3.  **Metadaten-Analyse**: Untersuchung der physischen Dateistruktur (z. B. freie Seiten/Free-Lists in SQLite, um gelöschte Datensätze zu identifizieren).

---

## 4. Konkrete "Take-Aways" zur Härtung von GhostAudit

Basierend auf den Profi-Recherchen schlagen wir folgende Härtungsmaßnahmen für GhostAudit V7 vor:

### 💡 Vorschlag 1: Vorwärtssicherheit (Forward-Secure Keys)
*   **Konzept**: Statt einen statischen kryptografischen Schlüssel für das HMAC-Shuffling und die Payload-Absicherung zu nutzen, implementieren wir eine **Key-Evolution-Chain**.
*   **Umsetzung**:
    1.  Bei jedem Schreiben eines Events (Slot-Schreibvorgang) wird der aktuelle Teilschlüssel gehasht: $K_{\text{new}} = \text{HMAC}(K_{\text{old}}, \text{"evolve"})$.
    2.  Der alte Schlüssel $K_{\text{old}}$ wird im Memory überschrieben.
    3.  Ein Angreifer, der später das System infiziert, kann historische Log-Fragmente nicht nachträglich manipulieren oder entschlüsseln, weil er die alten temporären Schlüssel nicht berechnen kann.

### 💡 Vorschlag 2: Externe Verankerung (Anchoring) & Merkle-Baum
*   **Konzept**: Um "Tail Truncation" (Löschen der neuesten Slots) zu verhindern, sollte der Root-Hash über alle aktiven Slots periodisch an einen externen Dienst oder eine Datei übertragen werden.
*   **Umsetzung**:
    *   Wir berechnen einen Merkle-Root-Hash aus den Hashes aller 5 Slots.
    *   Eine Methode `get_verification_digest()` exportiert diesen Root-Hash. Der Benutzer kann diesen auf einem WORM-Speicher, einem externen Syslog-Server oder per E-Mail sichern.

### 💡 Vorschlag 3: Robustes LSB-Matching für `trust_score`
*   **Konzept**: Um statistische Anomalien im Float-Kanal zu verhindern (was für Forensiker ein Alarmsignal ist), ersetzen wir das LSB nicht stumpf.
*   **Umsetzung**:
    *   Wenn das gewünschte Bit nicht mit dem LSB der Mantisse übereinstimmt, addieren oder subtrahieren wir zufällig $0.000001$ (den kleinsten Skalierungsschritt).
    *   Dadurch bleibt die statistische Verteilung der Float-Werte natürlicher.

### 💡 Vorschlag 4: SIEM-kompatibler JSON-Lines Export
*   **Konzept**: Forensiker arbeiten mit standardisierten Formaten.
*   **Umsetzung**:
    *   Ergänzung einer Methode `export_recovered_logs(format="jsonl")`, die die wiederhergestellten Logs im JSON-Lines-Format ausgibt, bereit zum Import in Splunk oder ELK-Stack.

### 💡 Vorschlag 5: Canary-Köder (Deception Technology)
*   **Konzept**: Der Angreifer soll durch gefälschte Audit-Tabellen abgelenkt und detektiert werden.
*   **Umsetzung**:
    *   In die Scheinentitäten von `audit_log` und `audit_archive` streuen wir spezielle Köder-Einträge (Canary Rows).
    *   Wenn ein Angreifer diese liest oder verändert, löst dies im Hintergrund (z. B. über einen intelligenten SQLite-Trigger) eine Benachrichtigung aus.
