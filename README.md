# suricata-ids-offensive-defensive
Déploiement d'un IDS/IPS Suricata sur environnement GNS3 — détection d'attaques réelles (SQLi, XSS, Nmap) avec visualisation des alertes via scripts Python.


#  Surveillance réseau et détection d'intrusions avec Suricata

> Projet académique — ENSA Oujda | Génie Sécurité Informatique & Cybersécurité  
> **Approche Offensive & Défensive** | IDS/IPS | Analyse du trafic réseau

---

## Présentation

Ce projet met en place une **architecture complète de surveillance de sécurité réseau** basée sur **Suricata** comme moteur IDS/IPS, déployé sur une topologie réseau simulée sous **GNS3**.

L'objectif n'était pas seulement de lancer des attaques, mais de **comprendre le comportement du trafic malveillant**, d'analyser les signatures de détection et de visualiser les alertes générées par un système de détection d'intrusion réel.

---

##  Objectifs

- Concevoir une topologie réseau fonctionnelle sous GNS3 avec un attaquant, une cible et une machine de supervision
- Configurer le **port mirroring** sur un switch pour rediriger tout le trafic vers Suricata
- Déployer Suricata en **mode IDS** (détection) puis en **mode IPS** (prévention)
- Simuler des attaques réelles et analyser les alertes générées
- Évaluer les performances et les limites de Suricata dans ce scénario

---





##  Outils & Technologies

| Outil | Rôle |
|-------|------|
| **Suricata** | Moteur IDS/IPS — inspection profonde des paquets & génération d'alertes |
| **GNS3** | Simulation de la topologie réseau |
| **Kali Linux** | Machine d'attaque |
| **Ubuntu Server** | Serveur web hébergeant la cible (DVWA) |
| **DVWA** | Application web volontairement vulnérable (cible) |
| **Python** | Scripts personnalisés d'analyse des logs avec interface graphique |

---

##  Scénarios d'attaques simulés

1. **Injection SQL** — via `sqlmap` contre DVWA
2. **Reconnaissance réseau** — scan de ports avec `Nmap`
3. **Cross-Site Scripting (XSS)** — attaques HTTP sur DVWA

Toutes les attaques ont été capturées et détectées par Suricata en temps réel.

---

##  Résultats & Visualisation

Deux scripts Python personnalisés ont été développés pour analyser les logs `eve.json` de Suricata :

**Script 1 — Analyseur interactif en ligne de commande**
- Lecture et parsing du fichier `eve.json`
- Affichage interactif et détaillé des alertes

**Script 2 — Dashboard avec interface graphique**
- Diagrammes circulaires (répartition des catégories)
- Graphiques à barres (top signatures)
- Timeline (évolution temporelle des alertes)
- Heatmap (concentration des alertes)
- Carte réseau (connexions entre IPs)
- Export en rapports HTML, CSV et PNG

---

##  Résultats clés

-  Suricata a détecté avec succès **toutes les attaques simulées**
-  Règles de détection personnalisées (`local.rules`) créées et validées
-  Visibilité en temps réel sur le trafic malveillant
-  Alertes précises et exploitables générées depuis `fast.log` et `eve.json`

---

## Structure du dépôt

```
├── rapport.pdf          # Rapport complet du projet
├── scripts/
│   ├── analyzer_cli.py  # Analyseur interactif en ligne de commande
│   └── dashboard_gui.py # Dashboard avec interface graphique
```

---

##  Perspectives futures
- Passage de Suricata en **mode IPS complet** pour bloquer activement les attaques
- Intégration avec **Kibana** pour une visualisation avancée des logs
- Extension de la surveillance à d'autres services réseau
- Renforcement et optimisation des règles de détection

---

##  Auteurs

- **Marwa Boualam** — [GitHub](https://github.com/MarwaBoualam) | [LinkedIn](https://www.linkedin.com/in/marwa-boualam-482b57217/)
- Boulal Ismail
- Mellouk Aya

**Encadrant :** M. OUBAHA Jawad  
**Établissement :** ENSA Oujda — 2ème année, Sécurité Informatique & Cybersécurité  
**Date :** Novembre 2025

