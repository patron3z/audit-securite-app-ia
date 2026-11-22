---
name: "audit-securite-app-ia"
description: "Audit de sécurité d'une app codée avec l'IA (Next.js, Supabase, Vercel, n8n, React Native) : secrets exposés, RLS, injection de prompt, paiements falsifiables, IDOR, uploads. Pour « audite mon app », « est-ce que mon app est sécure »."
---

# Audit sécurité d'app codée avec l'IA

Adapté de « AI-Generated Code Security Auditor » (msitarzewski/agency-agents, licence MIT), ajusté à une stack typique d'app codée avec l'IA : Next.js/React sur Vercel, Supabase, React Native/Expo, workflows n8n, appels à des LLM.

Principe : le code écrit par un assistant est optimisé pour la démo, pas pour la production. Il échoue de façon prévisible. Trouver ces failles avant un attaquant, prouver qu'elles sont réelles, donner une correction applicable en un commit.

Ici on audite le CODE et la BASE DE DONNÉES.

## Règles critiques

- **Preuve avant affirmation** : chaque constat = ligne exacte + exploit concret + correction. Jamais « possible problème, à investiguer ».
- **Lecture seule par défaut** : rapporter, ne jamais modifier ni supprimer de fichiers pendant l'audit. Les corrections se font ensuite, constat par constat, avec l'accord de l'utilisateur.
- **Un secret exposé est déjà brûlé** : chaque constat de secret inclut l'étape de rotation chez le fournisseur. L'enlever du code ne suffit pas.
- **Ne jamais réafficher un secret** : type, emplacement, aperçu masqué (ex. `sk-proj-…a9F2`). Jamais la valeur.
- **Faux négatif > faux positif** sur les vérifications heuristiques. Un outil qui crie au loup se fait ignorer.
- **Jamais de « % sécuritaire » ni de « conforme »** : dire ce qui a été vérifié, ce qui ne l'a pas été, le niveau de confiance.

## Les 4 familles à chasser

### 1. Secrets qui atteignent le client (CWE-798)
- Clés en dur dans du code client : clés API, jetons, URL de BD, clés privées collées « juste pour tester ».
- Secrets derrière un préfixe exposé au navigateur : `NEXT_PUBLIC_`, `VITE_`, `PUBLIC_`, `EXPO_PUBLIC_`. Une app Expo compilée expose tout ce qui est dans le bundle.
- Clé Supabase `service_role` importée n'importe où côté client : elle contourne toute la RLS.
- Variables d'env Vercel marquées pour le client alors qu'elles devraient rester serveur.
- Credentials en clair dans des JSON de workflows n8n exportés et commités.
- **NE PAS signaler** (conçu pour être public) : clé anon Supabase, clé publishable Stripe, client ID PayPal public, clé projet PostHog. Pour l'anon Supabase, la vraie barrière est la RLS.

### 2. RLS Supabase qui a juste l'air activée (CWE-862 / CWE-863)
- « RLS activée » est une affirmation à vérifier. Utiliser le MCP Supabase (`list_tables`, `execute_sql` en lecture, `get_advisors` sécurité) si connecté.
- Table publique sans RLS : la clé anon lit tout.
- Politique `USING (true)` : RLS « on », mais tout le monde lit tout.
- RLS on sans aucune politique : tout est refusé (l'app brise, souvent « réglée » ensuite par un `USING (true)`).
- Buckets de storage lisibles par tous (`storage.objects` avec `USING (true)`), ex. photos de jobs, pièces d'identité, contrats.
- Autorisation basée sur `user_metadata.role` : n'importe quel utilisateur connecté peut modifier son propre `user_metadata` et se donner le rôle admin. Utiliser `app_metadata` (serveur seulement).
- Edge functions sans vérification d'auth.
- Correction type : `create policy "proprio lit ses jobs" on public.jobs for select using ( auth.uid() = user_id );`

### 3. Entrée non fiable dans les instructions du modèle (CWE-1426, OWASP LLM01 ; + LLM06 si outils)
- Tracer l'entrée (`req.body`, query params, `.json()`, formulaires, webhooks n8n, courriels entrants) jusqu'à l'appel LLM.
- Moyen : entrée concaténée dans le system prompt ou dans une seule chaîne instruction + entrée.
- Élevé : même chose sur un appel qui a des outils/function calling (ex. créer une facture, rembourser, envoyer un courriel, écrire en BD).
- **NE PAS signaler** : entrée dans son propre message de rôle `user`, sans outils.
- Toujours dire que c'est heuristique, confiance moyenne, à vérifier à la main.

### 4. Le serveur fait confiance au client (les 14 attaques classiques)
Règle : tout ce qui vient du navigateur (prix, quantité, rôle, ID, fichier, nom) peut être modifié. Le serveur doit tout revérifier. Passer cette checklist sur chaque route API, server action, edge function et webhook :

| # | Attaque | Chercher dans le code | Correction attendue |
|---|---|---|---|
| 1 | Script dans le username (XSS, CWE-79) | `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, rendu de markdown non nettoyé | Échapper la sortie, DOMPurify si HTML nécessaire, en-tête CSP |
| 2 | Changer l'ID dans l'URL (IDOR, CWE-639) | `findById(params.id)` / `.eq('id', id)` sans filtre par `user_id` ; requêtes avec `service_role` | Vérifier la propriété côté serveur ou par RLS. Un UUID n'est pas une protection |
| 3 | Taper /admin (CWE-284) | Pages admin protégées seulement par un bouton caché ou un check côté client | Vérifier le rôle (`app_metadata`) dans le middleware et dans chaque route admin |
| 4 | Clé API dans le navigateur (CWE-798) | → famille 1 | → famille 1 |
| 5 | Injection de prompt (LLM01) | → famille 3 | → famille 3 ; confirmation humaine avant toute action sensible |
| 6 | Admin à l'inscription (mass assignment, CWE-915) | `insert(req.body)`, spread `...body` dans un update, `role` accepté du client, `user_metadata.role` | Liste blanche des champs (Zod), rôle décidé par le serveur, RLS qui bloque l'update de `role` |
| 7 | Modifier le prix (CWE-602) | `price`/`amount` lus de `req.body` puis envoyés à Stripe/PayPal | Prix lu en BD ou via `price` ID Stripe, jamais du client |
| 8 | Faux paiement (CWE-345) | Commande marquée payée sur la `success_url` ou par un appel client | Seul un webhook à signature vérifiée (`stripe.webhooks.constructEvent`) marque payé ; idempotence sur l'event ID |
| 9 | Utiliser un code 100 fois (race condition, CWE-362) | Lecture « déjà utilisé ? » puis écriture séparée ; pas de contrainte unique | Transaction atomique / `UPDATE ... WHERE used = false RETURNING`, contrainte unique, rate limit |
| 10 | Commander -1 item (CWE-20) | Quantités, montants, pourboires non validés côté serveur | Schéma Zod : entier, min 1, max raisonnable ; recalculer le total côté serveur |
| 11 | Deviner le code de connexion (CWE-307) | OTP/code promo/reset sans limite d'essais ; codes courts ou sans expiration | Rate limit par IP et par compte, blocage temporaire, expiration courte, codes ≥ 6 chiffres |
| 12 | Interroger la BD (injection SQL, CWE-89) | Template strings dans `sql`, `.rpc` avec SQL dynamique, `raw()` | Requêtes paramétrées / ORM ; jamais de concaténation |
| 13 | .env dans Git (CWE-540) | `.env*` suivi par git ou dans l'historique (`git log --all -- .env`) ; `.gitignore` absent | `.gitignore`, gitleaks en pre-commit/CI, **rotation de toutes les clés** (purger l'historique ne suffit pas) |
| 14 | Uploader un fichier qui n'est pas une photo (CWE-434) | Validation seulement par extension ou `Content-Type` client ; fichiers servis depuis le serveur web | Vérifier le vrai type (magic bytes), renommer, limiter la taille, stocker dans Supabase Storage/S3 avec politique privée, ne jamais exécuter |

Pour chaque ligne, le constat suit le format du rapport : fichier:ligne, exploit concret (« envoyer `quantity: -1` à `/api/checkout` donne un total négatif »), correction en un commit. Si une ligne n'a pas pu être vérifiée (ex. pas de code de paiement), l'écrire dans « Pas vérifié ».

## Processus

1. **Scanner au repos** : lire le repo (ou les fichiers fournis) sans rien envoyer à l'extérieur. Router par type : code client et bundles → secrets ; SQL/migrations et BD live → RLS ; appels SDK LLM et workflows n8n → injection ; routes API, server actions, edge functions, webhooks et formulaires → checklist de la famille 4. Si un secret est trouvé, chercher les autres : un assistant qui en a mis un en dur en a souvent mis plusieurs.
2. **Trier et expliquer** : du pire au moins grave, en français simple d'abord, CWE ensuite. Pour chaque constat : source, point d'arrivée, exploit concret, correction en un commit.
3. **Corriger avec l'utilisateur** : proposer les corrections une par une ou par sévérité. Jamais tout d'un coup derrière son dos.
4. **Re-scanner et dire la vérité** : comparer au scan précédent : résolu, encore présent, nouveau. Confirmer que les rotations de secrets ont été faites.

## Format du rapport

```
## Scan : N constats (X critiques, Y élevés, Z moyens, W faibles) — local, rien envoyé

1. [CRITIQUE] Clé service_role dans du code client — app/lib/supabase.ts:4 (CWE-798)
   Pourquoi : contourne toute la RLS ; n'importe qui lit toutes les lignes.
   Correction : déplacer dans une route serveur, utiliser la clé anon côté client. FAIRE LA ROTATION dans le dashboard Supabase.
2. ...

Vérifié : … | Pas vérifié : … | Confiance : …
Re-scanner après les corrections.
```

## Style

Calme, sceptique, précis. Pas de morale sur le fait de coder avec l'IA. Montrer la ligne, l'exploit, la correction, dans cet ordre. Répondre dans la langue de l'utilisateur.
