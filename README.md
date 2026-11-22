# Audit de sécurité pour les apps codées avec l'IA

Skill Claude (Claude Code et claude.ai) qui audite une app écrite avec un assistant IA — Next.js / React sur Vercel, Supabase, React Native / Expo, workflows n8n, appels à des LLM — et trouve les failles prévisibles avant un attaquant.

Chaque constat est prouvé : **fichier:ligne, exploit concret, correction en un commit**. L'audit est en lecture seule et n'affiche jamais un secret en clair.

## Ce qu'il cherche

1. **Secrets exposés** : clés dans le code client, préfixes `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_`, clé `service_role` Supabase, `.env` dans Git, credentials dans des workflows n8n exportés.
2. **RLS Supabase** : tables sans RLS, politiques `USING (true)`, buckets publics, rôle stocké dans `user_metadata`.
3. **Injection de prompt** : entrée utilisateur qui atteint les instructions d'un LLM, surtout quand il a des outils.
4. **Le serveur fait confiance au client** : 14 attaques classiques.

| # | Attaque | Correction attendue |
|---|---|---|
| 1 | Script dans le username (XSS) | Échapper la sortie, DOMPurify, en-tête CSP |
| 2 | Changer l'ID dans l'URL (IDOR) | Vérifier la propriété côté serveur ou par RLS |
| 3 | Taper /admin | Rôle vérifié (`app_metadata`) dans chaque route admin |
| 4 | Clé API dans le navigateur | Clés secrètes côté serveur seulement, rotation |
| 5 | Injection de prompt | Entrée isolée, outils minimaux, confirmation humaine |
| 6 | Admin à l'inscription (mass assignment) | Liste blanche des champs, rôle décidé par le serveur |
| 7 | Modifier le prix | Prix lu en BD ou price ID Stripe |
| 8 | Faux paiement | Webhook à signature vérifiée seulement |
| 9 | Utiliser un code 100 fois (race condition) | Transaction atomique, contrainte unique |
| 10 | Commander -1 item | Schéma Zod côté serveur, total recalculé |
| 11 | Deviner le code de connexion | Rate limit, blocage, expiration courte |
| 12 | Injection SQL | Requêtes paramétrées / ORM |
| 13 | `.env` dans Git | `.gitignore`, gitleaks, rotation des clés |
| 14 | Uploader un fichier qui n'est pas une photo | Vrai type vérifié, renommé, stockage privé |

## Installer

**Claude Code**

```bash
npx skills add patron3z/audit-securite-app-ia
```

ou à la main : copier le dossier `skills/audit-securite-app-ia` dans `~/.claude/skills/`.

**claude.ai** : zipper le dossier `skills/audit-securite-app-ia` (le `SKILL.md` à la racine du zip) et l'ajouter dans Paramètres → Skills.

Ensuite : « audite mon app » avec ton repo ou tes fichiers.

## Crédit et licence

Adapté de « AI-Generated Code Security Auditor » dans [msitarzewski/agency-agents](https://github.com/msitarzewski/agency-agents) (MIT). Ce repo est sous licence MIT ; garder ce crédit en redistribuant.
