# Rapport d’Audit de Sécurité

**Projet : VulnerableLightApp**  
**Auditeur : Aziz Khalfallah**  
**Période d’audit : Mai 2025**

---

## 1. Contexte de l’audit

Dans le cadre de son programme de sécurité informatique, l’entreprise ABC (30 collaborateurs, spécialisée dans le développement de logiciels) a sollicité un audit de sécurité portant sur l’une de ses applications internes, VulnerableLightApp. Cette application repose sur une API REST et interagit avec l’Active Directory de l’entreprise. L’infrastructure actuelle est composée d’un contrôleur de domaine Windows et d’un serveur Linux isolé du domaine.

L’objectif de cet audit est de mesurer le niveau d’exposition de l’application à des attaques connues, de vérifier la robustesse des mécanismes d’authentification et de contrôle d’accès, et de formuler des recommandations adaptées.

---

## 2. Méthodologie et environnement

L’audit a été mené sur un clone de l’application lancé en local. Aucune donnée réelle de production n’a été impliquée.

**Outils utilisés :**

- Postman pour la manipulation des requêtes HTTP  
- Snyk CLI pour l’analyse des vulnérabilités de dépendances  
- Inspection manuelle du code source (.NET / C#)

**Tests réalisés :**

- Fuzzing de l’API  
- Injection logique et test de contournement  
- Analyse statique des routes et entrées utilisateur

---

## 3. Vulnérabilités identifiées

### 3.1. Contournement d’authentification (bypass par injection)

**Description :**  
La route `/login` est vulnérable à une injection logique dans le champ `username`. En utilisant un payload de type `admin' OR '1'='1`, il est possible de passer outre les contrôles d’authentification.

**Payload utilisé :**

json
{
  "username": "admin' OR '1'='1",
  "password": "irrelevant"
}
**Impact :**  
Accès administrateur non autorisé.

**Gravité :** Critique

**Recommandations :**  
- Utiliser des requêtes paramétrées  
- Mettre en place une bibliothèque ORM sécurisée

---

### 3.2. Accès non contrôlé aux routes sensibles

**Description :**  
Les routes `/admin` et `/config` acceptent un token JWT sans vérifier le rôle associé. Un token modifié avec un rôle "user" permet d’accéder aux fonctions d’administration.

**Impact :**  
Modification non autorisée des configurations.

**Gravité :** Élevée

**Recommandations :**  
- Vérifier systématiquement le rôle utilisateur  
- Retourner une erreur 403 en cas d’accès non autorisé


3.3. Fuite d’informations techniques via les en-têtes HTTP
Description :
Le serveur expose des en-têtes techniques (exemple : X-Powered-By: Express), facilitant le fingerprinting.

### 3.3. Fuite d’informations techniques via les en-têtes HTTP

**Description :**  
Le serveur expose des en-têtes techniques (exemple : `X-Powered-By: Express`), facilitant le fingerprinting.

**Impact :**  
Aide à la préparation d’attaques ciblées.

**Gravité :** Moyenne

**Recommandations :**  
- Supprimer ou masquer ces en-têtes  
- Utiliser un middleware comme Helmet

---

### 3.4. Injection XML (XXE et XML Injection)

**Description :**  
La route `/Contract` accepte un paramètre XML non filtré, traité par `System.Xml.XmlReader.Create` sans désactivation des entités externes. Cela rend possible une attaque XXE (XML External Entity) permettant la lecture de fichiers locaux ou l’exfiltration de données.

**Extrait de code vulnérable :**
https://github.com/AzizKhalfallah5/imagesimages
```csharp
app.MapGet("/Contract", async (string i) => 
    await Task.FromResult(
        VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))
).WithOpenApi();

Impact :

Exfiltration de données sensibles

Modifications non autorisées via injection XML

Gravité : Élevée

Recommandations :

Désactiver la résolution des entités externes

Valider strictement les entrées XML

Utiliser des bibliothèques sécurisées pour le parsing XML

-- INSÉRER ICI L’IMAGE "Capture d'écran 2025-05-16 085458.png" --

3.5. Désérialisation non sécurisée JSON
Description :
La méthode JsonConvert.DeserializeObject est utilisée avec l’option TypeNameHandling.All, permettant la désérialisation arbitraire de types. Cela peut conduire à l’exécution de code arbitraire via des payloads JSON malicieux.

Extrait de code vulnérable :

csharp
Copier
Modifier
JsonConvert.DeserializeObject<object>(Json, new JsonSerializerSettings() {
    TypeNameHandling = TypeNameHandling.All
});
Impact :
Exécution de code à distance.

Gravité : Critique

Recommandations :

Éviter l’usage de TypeNameHandling.All

Restreindre les types autorisés à désérialiser

Valider les données JSON avec un schéma

4. | Vulnérabilité                           | Gravité  | Statut     |
| --------------------------------------- | -------- | ---------- |
| Bypass authentification                 | Critique | Expliqué   |
| Contrôle insuffisant des autorisations | Élevée   | Prouvé     |
| Fuite d'information technique           | Moyenne  | Observable |
| Injection XML (XXE & XML Injection)     | Élevée   | Démontré   |
| Désérialisation non sécurisée           | Critique | Démontré   |


---

## Recommandations générales

- Implémenter des requêtes sécurisées et éviter les injections  
- Renforcer la gestion des rôles et des autorisations  
- Supprimer les informations techniques dans les en-têtes HTTP  
- Filtrer et valider toutes les entrées XML et JSON  
- Mettre en place des scans réguliers avec Snyk et autres outils de sécurité  

---

## 5. Conclusion managériale

L’audit réalisé sur **VulnerableLightApp** a révélé des vulnérabilités majeures pouvant gravement compromettre la sécurité du système d’information d’ABC. Ces failles sont principalement dues à un contrôle d’accès insuffisant, à des faiblesses dans la validation des données, et à une mauvaise configuration des services.

Il est impératif d’intégrer une démarche **DevSecOps**, avec une revue continue du code et des tests automatisés de sécurité. La mise en place rapide des recommandations permettra de réduire significativement les risques d’intrusion et de fuite de données.


