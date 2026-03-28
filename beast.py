# ============================================================================
# SURICATA WINDOWS ANALYZER - Version VSCode
# Copiez-collez CE CODE ENTIER dans VSCode
# ============================================================================

import json
import os
from collections import Counter
from datetime import datetime
import webbrowser
import sys

class SuricataVSCodeAnalyzer:
    def __init__(self):
        # Chemin automatique vers le fichier sur le Bureau
        self.desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        self.eve_file = os.path.join(self.desktop, "eve.json")
        
        self.alerts = []
        self.stats = {}
        
        print("=" * 70)
        print("🔍 SURICATA ANALYZER - VERSION VSCODE")
        print("=" * 70)
        
    def find_eve_file(self):
        """Cherche le fichier eve.json automatiquement"""
        print(f"📁 Recherche de eve.json sur le Bureau...")
        
        # Vérifier le chemin par défaut
        if os.path.exists(self.eve_file):
            print(f"✅ Fichier trouvé: {self.eve_file}")
            return self.eve_file
        
        # Chercher dans d'autres emplacements communs
        search_paths = [
            os.path.join(self.desktop, "eve.json"),
            os.path.join(os.path.expanduser("~"), "Downloads", "eve.json"),
            os.path.join(self.desktop, "suricata", "eve.json"),
            os.path.join(os.getcwd(), "eve.json")
        ]
        
        for path in search_paths:
            if os.path.exists(path):
                print(f"✅ Fichier trouvé: {path}")
                self.eve_file = path
                return path
        
        # Si pas trouvé, demander
        print("❌ Fichier non trouvé automatiquement")
        print("\n📌 Où avez-vous enregistré eve.json ?")
        print("1. Sur le Bureau (par défaut)")
        print("2. Dans les Téléchargements")
        print("3. Autre emplacement")
        
        choice = input("\nVotre choix (1-3): ").strip()
        
        if choice == "1":
            return self.eve_file
        elif choice == "2":
            self.eve_file = os.path.join(os.path.expanduser("~"), "Downloads", "eve.json")
        elif choice == "3":
            self.eve_file = input("Entrez le chemin complet: ").strip()
        
        return self.eve_file if os.path.exists(self.eve_file) else None
    
    def load_data(self):
        """Charge et analyse le fichier"""
        file_path = self.find_eve_file()
        
        if not file_path or not os.path.exists(file_path):
            print(f"\n❌ ERREUR: Impossible de trouver eve.json")
            print(f"   Placez le fichier sur votre Bureau Windows")
            print(f"   Ou modifiez le chemin dans le code")
            return False
        
        print(f"\n📊 Analyse de: {os.path.basename(file_path)}")
        print("-" * 70)
        
        try:
            # Vérifier la taille du fichier
            file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB
            print(f"📏 Taille du fichier: {file_size:.2f} MB")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                line_count = 0
                alert_count = 0
                
                # Barre de progression
                print("⏳ Chargement en cours...", end='', flush=True)
                
                for line in f:
                    line_count += 1
                    
                    # Afficher une progression tous les 1000 lignes
                    if line_count % 1000 == 0:
                        print('.', end='', flush=True)
                    
                    try:
                        event = json.loads(line.strip())
                        if event.get('event_type') == 'alert':
                            self.alerts.append(event)
                            alert_count += 1
                    except json.JSONDecodeError:
                        continue
                
                print()  # Nouvelle ligne après la progression
                
                print(f"\n✅ Chargement terminé!")
                print(f"   • Lignes analysées: {line_count:,}")
                print(f"   • Alertes trouvées: {alert_count:,}")
                
                if alert_count == 0:
                    print("\n⚠️  Aucune alerte détectée!")
                    print("   Vérifiez que Suricata génère bien des alertes")
                    return False
                
                return True
                
        except Exception as e:
            print(f"\n❌ Erreur: {e}")
            return False
    
    def quick_analysis(self):
        """Analyse rapide avec affichage coloré"""
        if not self.alerts:
            return
        
        print("\n" + "=" * 70)
        print("🚨 ANALYSE RAPIDE DES ALERTES")
        print("=" * 70)
        
        # Statistiques
        signatures = Counter()
        src_ips = Counter()
        severities = Counter()
        
        for alert in self.alerts:
            sig = alert.get('alert', {}).get('signature', 'Unknown')
            signatures[sig] += 1
            
            src_ip = alert.get('src_ip', 'Unknown')
            if src_ip != 'Unknown':
                src_ips[src_ip] += 1
            
            sev = alert.get('alert', {}).get('severity', 0)
            severities[sev] += 1
        
        # Sauvegarder
        self.stats = {
            'total_alerts': len(self.alerts),
            'signatures': signatures,
            'src_ips': src_ips,
            'severities': severities
        }
        
        # Affichage
        print(f"\n📈 STATISTIQUES:")
        print(f"   • Alertes totales: {len(self.alerts):,}")
        print(f"   • Signatures uniques: {len(signatures):,}")
        print(f"   • IPs sources uniques: {len([ip for ip in src_ips if ip != 'Unknown']):,}")
        
        # Calcul niveau de menace
        threat_score = 0
        for sev, count in severities.items():
            try:
                threat_score += int(sev) * count
            except:
                pass
        
        threat_level = threat_score / max(len(self.alerts), 1)
        
        if threat_level < 1.5:
            threat_text = "FAIBLE 🟢"
        elif threat_level < 2.5:
            threat_text = "MOYEN 🟡"
        else:
            threat_text = "ÉLEVÉ 🔴"
        
        print(f"   • Niveau de menace: {threat_text} ({threat_level:.2f}/3)")
        
        print(f"\n🔝 TOP 5 SIGNATURES:")
        for i, (sig, count) in enumerate(signatures.most_common(5), 1):
            sig_display = sig[:60] + '...' if len(sig) > 60 else sig
            print(f"   {i}. {sig_display}")
            print(f"      → {count} occurrences")
        
        print(f"\n🌐 TOP 5 IPs SOURCES:")
        for i, (ip, count) in enumerate(src_ips.most_common(5), 1):
            print(f"   {i}. {ip:15} → {count:4d} alertes")
        
        print(f"\n⚠️  RÉPARTITION DES SÉVÉRITÉS:")
        total = sum(severities.values())
        for sev in sorted(severities.keys()):
            count = severities[sev]
            percent = (count / total) * 100
            bar = "█" * int(percent / 2)
            
            if sev == 1:
                level = "Faible  "
            elif sev == 2:
                level = "Moyenne "
            else:
                level = "Élevée "
            
            print(f"   Niveau {sev} ({level}): {count:4d} ({percent:5.1f}%) {bar}")
    
    def generate_interactive_report(self):
        """Génère un rapport HTML interactif"""
        if not self.alerts:
            return
        
        print("\n📄 CRÉATION DU RAPPORT INTERACTIF...")
        
        # Données pour le rapport
        top_sigs = self.stats['signatures'].most_common(15)
        top_ips = self.stats['src_ips'].most_common(15)
        
        # HTML avec JavaScript pour l'interactivité
        html = f'''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Suricata Report - {datetime.now().strftime("%Y-%m-%d")}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f0f2f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }}
        .card h3 {{
            color: #555;
            margin-top: 0;
        }}
        .card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        th {{
            background: #667eea;
            color: white;
            cursor: pointer;
            user-select: none;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .tab-container {{
            margin: 30px 0;
        }}
        .tabs {{
            display: flex;
            gap: 5px;
            margin-bottom: 20px;
        }}
        .tab {{
            padding: 10px 20px;
            background: #e0e0e0;
            border: none;
            border-radius: 5px 5px 0 0;
            cursor: pointer;
        }}
        .tab.active {{
            background: white;
            font-weight: bold;
        }}
        .tab-content {{
            display: none;
            background: white;
            padding: 20px;
            border-radius: 0 8px 8px 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .tab-content.active {{
            display: block;
        }}
        .search-box {{
            padding: 10px;
            width: 100%;
            margin: 20px 0;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
        }}
        .alert-details {{
            background: #fff3cd;
            padding: 15px;
            margin: 10px 0;
            border-left: 5px solid #ffc107;
            border-radius: 5px;
            display: none;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
        .severity-1 {{ color: #28a745; }}
        .severity-2 {{ color: #ffc107; }}
        .severity-3 {{ color: #dc3545; }}
        .chart-container {{
            height: 300px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Rapport Suricata - Analyse Interactive</h1>
            <p>Généré le {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="cards">
            <div class="card">
                <h3>🚨 Alertes totales</h3>
                <div class="value">{self.stats['total_alerts']:,}</div>
            </div>
            <div class="card">
                <h3>🎯 Signatures</h3>
                <div class="value">{len(self.stats['signatures']):,}</div>
            </div>
            <div class="card">
                <h3>🌐 IPs sources</h3>
                <div class="value">{len([ip for ip in self.stats['src_ips'] if ip != 'Unknown']):,}</div>
            </div>
            <div class="card">
                <h3>📈 Taux détection</h3>
                <div class="value">100%</div>
            </div>
        </div>
        
        <div class="tab-container">
            <div class="tabs">
                <button class="tab active" onclick="showTab('signatures')">Signatures</button>
                <button class="tab" onclick="showTab('ips')">IPs Sources</button>
                <button class="tab" onclick="showTab('alerts')">Alertes récentes</button>
            </div>
            
            <div id="signatures" class="tab-content active">
                <h3>🔝 Top Signatures</h3>
                <input type="text" class="search-box" placeholder="Rechercher une signature..." onkeyup="searchTable('signatures-table', this)">
                <table id="signatures-table">
                    <thead>
                        <tr>
                            <th onclick="sortTable('signatures-table', 0)">#</th>
                            <th onclick="sortTable('signatures-table', 1)">Signature</th>
                            <th onclick="sortTable('signatures-table', 2)">Nombre</th>
                            <th onclick="sortTable('signatures-table', 3)">%</th>
                        </tr>
                    </thead>
                    <tbody>
        '''
        
        # Remplir le tableau des signatures
        for i, (sig, count) in enumerate(top_sigs, 1):
            percentage = (count / self.stats['total_alerts']) * 100
            html += f'''
                        <tr>
                            <td>{i}</td>
                            <td>{sig[:80]}{'...' if len(sig) > 80 else ''}</td>
                            <td>{count:,}</td>
                            <td>{percentage:.1f}%</td>
                        </tr>
            '''
        
        html += f'''
                    </tbody>
                </table>
            </div>
            
            <div id="ips" class="tab-content">
                <h3>🌐 Top IPs Sources</h3>
                <input type="text" class="search-box" placeholder="Rechercher une IP..." onkeyup="searchTable('ips-table', this)">
                <table id="ips-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>IP Address</th>
                            <th>Alertes</th>
                            <th>%</th>
                        </tr>
                    </thead>
                    <tbody>
        '''
        
        # Remplir le tableau des IPs
        for i, (ip, count) in enumerate(top_ips, 1):
            percentage = (count / self.stats['total_alerts']) * 100
            html += f'''
                        <tr>
                            <td>{i}</td>
                            <td>{ip}</td>
                            <td>{count:,}</td>
                            <td>{percentage:.1f}%</td>
                        </tr>
            '''
        
        html += f'''
                    </tbody>
                </table>
            </div>
            
            <div id="alerts" class="tab-content">
                <h3>🚨 Dernières Alertes</h3>
                <input type="text" class="search-box" placeholder="Filtrer les alertes..." onkeyup="filterAlerts(this)">
                <div id="alerts-container">
        '''
        
        # 20 dernières alertes
        for i, alert in enumerate(self.alerts[-20:], 1):
            sig = alert.get('alert', {}).get('signature', 'Unknown')
            src = alert.get('src_ip', 'Unknown')
            dst = alert.get('dest_ip', 'Unknown')
            sev = alert.get('alert', {}).get('severity', 0)
            time = alert.get('timestamp', '')[:19]
            proto = alert.get('proto', 'Unknown')
            
            sev_class = f'severity-{sev}'
            
            html += f'''
                    <div class="alert-item" data-signature="{sig}" data-src="{src}" data-severity="{sev}">
                        <strong>#{len(self.alerts) - 20 + i}</strong>
                        <span class="{sev_class}">[Niveau {sev}]</span>
                        <br>
                        {sig[:100]}
                        <br>
                        <small>📍 {src} → {dst} | {proto} | {time}</small>
                        <div class="alert-details" id="details-{i}">
                            <strong>Détails complets:</strong><br>
                            {json.dumps(alert, indent=2)}
                        </div>
                        <button onclick="toggleDetails({i})">Afficher détails</button>
                    </div>
            '''
        
        html += '''
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Fonction pour changer d'onglet
        function showTab(tabName) {
            // Masquer tous les onglets
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Désactiver tous les boutons
            document.querySelectorAll('.tab').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Afficher l'onglet sélectionné
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }
        
        // Fonction de recherche dans les tables
        function searchTable(tableId, input) {
            const filter = input.value.toUpperCase();
            const table = document.getElementById(tableId);
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    if (cell) {
                        if (cell.textContent.toUpperCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                
                rows[i].style.display = found ? '' : 'none';
            }
        }
        
        // Fonction de tri des tables
        function sortTable(tableId, column) {
            const table = document.getElementById(tableId);
            const rows = Array.from(table.rows).slice(1);
            const isNumeric = column === 2 || column === 3;
            
            rows.sort((a, b) => {
                const aVal = a.cells[column].textContent;
                const bVal = b.cells[column].textContent;
                
                if (isNumeric) {
                    return parseFloat(aVal.replace(/,/g, '')) - parseFloat(bVal.replace(/,/g, ''));
                } else {
                    return aVal.localeCompare(bVal);
                }
            });
            
            // Réorganiser les lignes
            rows.forEach(row => table.tBodies[0].appendChild(row));
        }
        
        // Filtrer les alertes
        function filterAlerts(input) {
            const filter = input.value.toUpperCase();
            const alerts = document.querySelectorAll('.alert-item');
            
            alerts.forEach(alert => {
                const text = alert.textContent.toUpperCase();
                const signature = alert.dataset.signature.toUpperCase();
                const src = alert.dataset.src.toUpperCase();
                const severity = alert.dataset.severity;
                
                if (text.includes(filter) || 
                    signature.includes(filter) || 
                    src.includes(filter) ||
                    severity.includes(filter)) {
                    alert.style.display = '';
                } else {
                    alert.style.display = 'none';
                }
            });
        }
        
        // Afficher/masquer les détails
        function toggleDetails(id) {
            const details = document.getElementById('details-' + id);
            const button = event.target;
            
            if (details.style.display === 'block') {
                details.style.display = 'none';
                button.textContent = 'Afficher détails';
            } else {
                details.style.display = 'block';
                button.textContent = 'Masquer détails';
            }
        }
        
        // Initialisation
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Rapport Suricata chargé avec succès!');
        });
    </script>
</body>
</html>
        '''
        
        # Sauvegarder le rapport
        report_name = f"suricata_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = os.path.join(self.desktop, report_name)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"✅ Rapport généré: {report_path}")
        print("🌐 Ouverture dans le navigateur...")
        
        # Ouvrir automatiquement
        webbrowser.open(f'file://{report_path}')
    
    def export_to_excel(self):
        """Exporte les données en format Excel/CSV"""
        if not self.alerts:
            return
        
        print("\n💾 EXPORT DES DONNÉES...")
        
        # CSV simple
        csv_name = f"suricata_alerts_{datetime.now().strftime('%Y%m%d')}.csv"
        csv_path = os.path.join(self.desktop, csv_name)
        
        with open(csv_path, 'w', encoding='utf-8') as f:
            # En-têtes
            f.write("Timestamp,Signature,Source IP,Destination IP,Severity,Protocol,Category\n")
            
            # Données
            for alert in self.alerts:
                timestamp = alert.get('timestamp', '').replace(',', ' ')
                signature = alert.get('alert', {}).get('signature', '').replace(',', ';')
                src_ip = alert.get('src_ip', '')
                dst_ip = alert.get('dest_ip', '')
                severity = alert.get('alert', {}).get('severity', '')
                protocol = alert.get('proto', '')
                category = alert.get('alert', {}).get('category', '').replace(',', ';')
                
                f.write(f'"{timestamp}","{signature}","{src_ip}","{dst_ip}",{severity},{protocol},"{category}"\n')
        
        print(f"📊 CSV exporté: {csv_path}")
        
        # Fichier de statistiques
        stats_name = f"suricata_stats_{datetime.now().strftime('%Y%m%d')}.txt"
        stats_path = os.path.join(self.desktop, stats_name)
        
        with open(stats_path, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("STATISTIQUES SURICATA\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Date d'analyse: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Fichier source: {os.path.basename(self.eve_file)}\n\n")
            
            f.write(f"Alertes totales: {self.stats['total_alerts']:,}\n")
            f.write(f"Signatures uniques: {len(self.stats['signatures']):,}\n")
            f.write(f"IPs sources uniques: {len([ip for ip in self.stats['src_ips'] if ip != 'Unknown']):,}\n\n")
            
            f.write("Top 10 Signatures:\n")
            for sig, count in self.stats['signatures'].most_common(10):
                f.write(f"  {sig[:80]}: {count:,}\n")
        
        print(f"📈 Statistiques exportées: {stats_path}")
    
    def run(self):
        """Exécute l'analyse complète"""
        print("\n" + "=" * 70)
        print("🚀 DÉMARRAGE DE L'ANALYSE")
        print("=" * 70)
        
        # Étape 1: Charger les données
        if not self.load_data():
            print("\n❌ Impossible de continuer sans données.")
            input("\nAppuyez sur Entrée pour quitter...")
            return
        
        # Étape 2: Analyse rapide
        self.quick_analysis()
        
        # Étape 3: Menu interactif
        while True:
            print("\n" + "=" * 70)
            print("📋 MENU PRINCIPAL")
            print("=" * 70)
            print("1. 🔄 Ré-analyser le fichier")
            print("2. 📊 Générer rapport HTML interactif")
            print("3. 💾 Exporter données (CSV + Stats)")
            print("4. 🚨 Voir alertes récentes")
            print("5. 🔍 Rechercher une signature")
            print("6. 🎯 Analyser une IP spécifique")
            print("7. 🚪 Quitter")
            
            choice = input("\nVotre choix (1-7): ").strip()
            
            if choice == "1":
                self.alerts = []
                if self.load_data():
                    self.quick_analysis()
            
            elif choice == "2":
                self.generate_interactive_report()
                print("\n✅ Rapport généré et ouvert dans votre navigateur!")
            
            elif choice == "3":
                self.export_to_excel()
                print("\n✅ Données exportées sur votre Bureau!")
            
            elif choice == "4":
                self.show_recent_alerts()
            
            elif choice == "5":
                self.search_signature()
            
            elif choice == "6":
                self.analyze_ip()
            
            elif choice == "7":
                print("\n👋 Au revoir! Merci d'avoir utilisé Suricata Analyzer.")
                break
            
            else:
                print("❌ Choix invalide. Essayez à nouveau.")
    
    def show_recent_alerts(self):
        """Affiche les alertes récentes"""
        if not self.alerts:
            return
        
        count = min(10, len(self.alerts))
        print(f"\n🚨 {count} DERNIÈRES ALERTES:")
        print("-" * 70)
        
        for i, alert in enumerate(self.alerts[-count:], 1):
            sig = alert.get('alert', {}).get('signature', 'Unknown')
            src = alert.get('src_ip', 'Unknown')
            dst = alert.get('dest_ip', 'Unknown')
            sev = alert.get('alert', {}).get('severity', 0)
            time = alert.get('timestamp', '')[:19]
            
            print(f"\n#{len(self.alerts) - count + i} - {time}")
            print(f"  Signature: {sig[:80]}")
            print(f"  Source: {src} → Destination: {dst}")
            print(f"  Sévérité: Niveau {sev}")
        
        input("\nAppuyez sur Entrée pour continuer...")
    
    def search_signature(self):
        """Recherche une signature spécifique"""
        if not self.alerts:
            return
        
        keyword = input("\n🔍 Mot-clé à rechercher: ").strip().lower()
        
        if not keyword:
            return
        
        results = []
        for alert in self.alerts:
            sig = alert.get('alert', {}).get('signature', '').lower()
            if keyword in sig:
                results.append(alert)
        
        print(f"\n✅ {len(results)} alertes trouvées avec '{keyword}'")
        
        if results:
            print("\nExemples:")
            for i, alert in enumerate(results[:5], 1):
                sig = alert.get('alert', {}).get('signature', 'Unknown')
                time = alert.get('timestamp', '')[:19]
                print(f"  {i}. {time} - {sig[:60]}...")
        
        input("\nAppuyez sur Entrée pour continuer...")
    
    def analyze_ip(self):
        """Analyse une IP spécifique"""
        if not self.alerts:
            return
        
        ip = input("\n🌐 IP à analyser: ").strip()
        
        if not ip:
            return
        
        alerts_from = [a for a in self.alerts if a.get('src_ip') == ip]
        alerts_to = [a for a in self.alerts if a.get('dest_ip') == ip]
        
        print(f"\n📊 Analyse de l'IP: {ip}")
        print(f"  • Alertes depuis cette IP: {len(alerts_from)}")
        print(f"  • Alertes vers cette IP: {len(alerts_to)}")
        print(f"  • Total: {len(alerts_from) + len(alerts_to)}")
        
        if alerts_from:
            print("\n  Top signatures depuis cette IP:")
            sigs_from = Counter()
            for alert in alerts_from:
                sig = alert.get('alert', {}).get('signature', 'Unknown')
                sigs_from[sig] += 1
            
            for sig, count in sigs_from.most_common(5):
                print(f"    • {sig[:50]}: {count}")
        
        input("\nAppuyez sur Entrée pour continuer...")

# ============================================================================
# POINT D'ENTRÉE PRINCIPAL
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("🖥️  SURICATA ANALYZER - READY FOR VSCODE")
    print("=" * 70)
    print("\n📌 Instructions:")
    print("  1. Collez ce code dans VSCode")
    print("  2. Sauvegardez-le (Ctrl+S)")
    print("  3. Exécutez-le (F5 ou Run)")
    print("  4. Suivez les instructions à l'écran")
    print("\n⚠️  Assurez-vous que 'eve.json' est sur votre Bureau Windows")
    print("=" * 70)
    
    # Créer et lancer l'analyseur
    analyzer = SuricataVSCodeAnalyzer()
    analyzer.run()
    
    # Garder la fenêtre ouverte
    input("\n🎯 Analyse terminée! Appuyez sur Entrée pour quitter...")