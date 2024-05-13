import tkinter as tk
from tkinter import messagebox
import requests
from bs4 import BeautifulSoup
import re
import nmap

# Fonction de scan pour les failles XSS, injections SQL et inclusion de fichiers
def scan_web():
    url = entry_url.get()  # Obtenir l'URL à partir de l'entrée utilisateur
    xss_vuln = False
    sql_vuln = False
    file_inclusion_vuln = False
    directory_traversal_vuln = False
    csrf_vuln = False
    sensitive_info_exposure_vuln = False
    command_injection_vuln = False
    weak_password_vuln = False
    session_fixation_vuln = False
    clickjacking_vuln = False
    
    try:
        # Envoyer une requête GET à l'URL spécifiée
        response = requests.get(url)
        
        # Analyse du contenu HTML avec BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        # Recherche de balises script dans le contenu HTML
        if soup.find('script'):
            messagebox.showwarning("XSS Vulnerability Detected", "XSS vulnerability detected in the response.")
            xss_vuln = True
        else:
            messagebox.showinfo("No XSS Vulnerability", "No XSS vulnerability detected in the response.")
        
        # Vérification des en-têtes HTTP pour détecter les injections SQL et l'inclusion de fichiers
        if 'sql' in response.headers.get('x-powered-by', '').lower() or 'sql' in response.headers.get('server', '').lower():
            messagebox.showwarning("SQL Injection Detected", "SQL injection vulnerability detected in the response headers.")
            sql_vuln = True
        else:
            messagebox.showinfo("No SQL Injection", "No SQL injection vulnerability detected in the response headers.")
        
        if 'file not found' in response.headers.get('server', '').lower():
            messagebox.showwarning("File Inclusion Detected", "File inclusion vulnerability detected in the response headers.")
            file_inclusion_vuln = True
        else:
            messagebox.showinfo("No File Inclusion", "No file inclusion vulnerability detected in the response headers.")
        
        # Test de faille : Traversée de répertoire
        if '../' in response.text:
            messagebox.showwarning("Directory Traversal Detected", "Directory traversal vulnerability detected in the response.")
            directory_traversal_vuln = True
        else:
            messagebox.showinfo("No Directory Traversal", "No directory traversal vulnerability detected in the response.")
        
        # Test de faille : CSRF
        if 'csrf_token' in response.text:
            messagebox.showwarning("CSRF Vulnerability Detected", "CSRF vulnerability detected in the response.")
            csrf_vuln = True
        else:
            messagebox.showinfo("No CSRF Vulnerability", "No CSRF vulnerability detected in the response.")
        
        # Test de faille : Exposition d'informations sensibles
        if 'password' in response.text:
            messagebox.showwarning("Sensitive Info Exposure Detected", "Sensitive information exposure vulnerability detected in the response.")
            sensitive_info_exposure_vuln = True
        else:
            messagebox.showinfo("No Sensitive Info Exposure", "No sensitive information exposure vulnerability detected in the response.")
        
        # Test de faille : Injection de commandes
        if re.search(r'\b(?:rm|ls|cat)\b', response.text):
            messagebox.showwarning("Command Injection Detected", "Command injection vulnerability detected in the response.")
            command_injection_vuln = True
        else:
            messagebox.showinfo("No Command Injection", "No command injection vulnerability detected in the response.")
        
        # Test de faille : Mot de passe faible
        if 'password' in response.text and len(response.text) < 8:
            messagebox.showwarning("Weak Password Detected", "Weak password vulnerability detected in the response.")
            weak_password_vuln = True
        else:
            messagebox.showinfo("No Weak Password", "No weak password vulnerability detected in the response.")
        
        # Test de faille : Fixation de session
        if 'Set-Cookie' in response.headers:
            messagebox.showwarning("Session Fixation Detected", "Session fixation vulnerability detected in the response headers.")
            session_fixation_vuln = True
        else:
            messagebox.showinfo("No Session Fixation", "No session fixation vulnerability detected in the response headers.")
        
        # Test de faille : Clickjacking
        if 'X-Frame-Options' not in response.headers:
            messagebox.showwarning("Clickjacking Detected", "Clickjacking vulnerability detected in the response headers.")
            clickjacking_vuln = True
        else:
            messagebox.showinfo("No Clickjacking", "No clickjacking vulnerability detected in the response headers.")
        
        # Scan Nmap
        nm = nmap.PortScanner()
        nm.scan(url, arguments='-A')
        nmap_report = nm.csv()
            
        # Appel à la fonction pour générer le rapport
        generate_report(url, xss_vuln, sql_vuln, file_inclusion_vuln, directory_traversal_vuln, csrf_vuln,
                        sensitive_info_exposure_vuln, command_injection_vuln, weak_password_vuln,
                        session_fixation_vuln, clickjacking_vuln, nmap_report)
            
    except requests.RequestException as e:
        messagebox.showerror("Error", f"Error occurred: {e}")

# Fonction pour générer le rapport
def generate_report(url, xss_vuln, sql_vuln, file_inclusion_vuln, directory_traversal_vuln, csrf_vuln,
                    sensitive_info_exposure_vuln, command_injection_vuln, weak_password_vuln,
                    session_fixation_vuln, clickjacking_vuln, nmap_report):
    report = f"Report for {url}:\n"
    if xss_vuln:
        report += "XSS vulnerability detected.\n"
    else:
        report += "No XSS vulnerability detected.\n"
    
    if sql_vuln:
        report += "SQL injection vulnerability detected.\n"
    else:
        report += "No SQL injection vulnerability detected.\n"
    
    if file_inclusion_vuln:
        report += "File inclusion vulnerability detected.\n"
    else:
        report += "No file inclusion vulnerability detected.\n"
    
    if directory_traversal_vuln:
        report += "Directory traversal vulnerability detected.\n"
    else:
        report += "No directory traversal vulnerability detected.\n"
    
    if csrf_vuln:
        report += "CSRF vulnerability detected.\n"
    else:
        report += "No CSRF vulnerability detected.\n"
    
    if sensitive_info_exposure_vuln:
        report += "Sensitive information exposure vulnerability detected.\n"
    else:
        report += "No sensitive information exposure vulnerability detected.\n"
    
    if command_injection_vuln:
        report += "Command injection vulnerability detected.\n"
    else:
        report += "No command injection vulnerability detected.\n"
    
    if weak_password_vuln:
        report += "Weak password vulnerability detected.\n"
    else:
        report += "No weak password vulnerability detected.\n"
    
    if session_fixation_vuln:
        report += "Session fixation vulnerability detected.\n"
    else:
        report += "No session fixation vulnerability detected.\n"
    
    if clickjacking_vuln:
        report += "Clickjacking vulnerability detected.\n"
    else:
        report += "No clickjacking vulnerability detected.\n"
    
    # Ajouter les résultats du scan Nmap au rapport
    report += "\nNmap Scan Results:\n"
    report += nmap_report
    
    # Affichage du rapport dans une boîte de dialogue
    messagebox.showinfo("Scan Report", report)

# Création de la fenêtre principale
root = tk.Tk()
root.title("Vulnerability Scanner")

# Création des widgets
label_url = tk.Label(root, text="Enter URL or IP:")
label_url.pack()

entry_url = tk.Entry(root)
entry_url.pack()

scan_button = tk.Button(root, text="Scan", command=scan_web)  # Lier la fonction de scan au bouton
scan_button.pack()

# Exécution de la boucle principale
root.mainloop()
