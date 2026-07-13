-- ════════════════════════════════════════════════════════════════
--  CANADO TECHNIQUE — SCHÉMA DE CERTIFICATION (PostgreSQL)
--  Sanction officielle APC / MENFP
--
--  Principe : une évaluation sommative est SIGNÉE, VERROUILLÉE et
--  IMMUABLE. Une reprise crée une NOUVELLE tentative — jamais un
--  écrasement. C'est ce qui rend le diplôme opposable.
-- ════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── UTILISATEURS & RÔLES ───────────────────────────────────────
CREATE TABLE utilisateurs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE NOT NULL,
  mot_de_passe  TEXT NOT NULL,                    -- bcrypt
  nom           TEXT NOT NULL,
  prenom        TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('etudiant','formateur','direction','admin')),
  actif         BOOLEAN NOT NULL DEFAULT TRUE,
  cree_le       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_users_role ON utilisateurs(role);

-- ── ÉTUDIANTS ──────────────────────────────────────────────────
CREATE TABLE etudiants (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  utilisateur_id UUID UNIQUE REFERENCES utilisateurs(id) ON DELETE SET NULL,
  matricule     TEXT UNIQUE NOT NULL,             -- ex. ELM-2026-0142
  nom           TEXT NOT NULL,
  prenom        TEXT NOT NULL,
  date_naissance DATE,
  telephone     TEXT,
  filiere       TEXT NOT NULL CHECK (filiere IN ('TRI','MEI','ELM','TEL')),
  cohorte       TEXT NOT NULL,                    -- ex. 2026-A
  statut        TEXT NOT NULL DEFAULT 'actif'
                CHECK (statut IN ('actif','suspendu','diplome','abandon')),
  inscrit_le    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_etu_filiere ON etudiants(filiere, cohorte);

-- ── MODULES (importés de data.json) ────────────────────────────
CREATE TABLE modules (
  code          TEXT PRIMARY KEY,                 -- ELM-17
  filiere       TEXT NOT NULL,
  annee         SMALLINT NOT NULL CHECK (annee IN (1,2)),
  titre         TEXT NOT NULL,
  enonce        TEXT,                             -- énoncé officiel de la compétence
  heures        SMALLINT NOT NULL,
  type_objectif TEXT NOT NULL CHECK (type_objectif IN ('comportement','situation')),
  seuil_points  SMALLINT,                         -- comportement : ex. 85
  seuil_criteres SMALLINT,                        -- situation : ex. 7
  total_criteres SMALLINT,                        -- situation : ex. 10
  actif         BOOLEAN NOT NULL DEFAULT TRUE
);

-- ── CRITÈRES D'ÉVALUATION (les 26 grilles officielles) ─────────
CREATE TABLE criteres (
  id            SERIAL PRIMARY KEY,
  module_code   TEXT NOT NULL REFERENCES modules(code) ON DELETE CASCADE,
  ordre         SMALLINT NOT NULL,
  libelle       TEXT NOT NULL,
  points        SMALLINT,                         -- NULL pour les modules de situation
  obligatoire   BOOLEAN NOT NULL DEFAULT FALSE,   -- « critères cochés » du guide
  UNIQUE (module_code, ordre)
);

-- ── INSCRIPTIONS AUX MODULES ───────────────────────────────────
CREATE TABLE inscriptions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  etudiant_id   UUID NOT NULL REFERENCES etudiants(id) ON DELETE CASCADE,
  module_code   TEXT NOT NULL REFERENCES modules(code),
  debut_le      DATE,
  UNIQUE (etudiant_id, module_code)
);

-- ── ÉVALUATIONS SOMMATIVES (le cœur : IMMUABLE) ────────────────
CREATE TABLE evaluations (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  etudiant_id   UUID NOT NULL REFERENCES etudiants(id) ON DELETE RESTRICT,
  module_code   TEXT NOT NULL REFERENCES modules(code),
  formateur_id  UUID NOT NULL REFERENCES utilisateurs(id),
  tentative     SMALLINT NOT NULL DEFAULT 1,
  date_epreuve  DATE NOT NULL,

  points_obtenus  SMALLINT,                       -- comportement
  criteres_valides SMALLINT,                      -- situation
  detail          JSONB NOT NULL,                 -- { "1": 10, "2": 0, ... } par critère

  verdique      BOOLEAN NOT NULL DEFAULT FALSE,   -- ⚠️ manquement grave sécurité → ÉCHEC
  motif_verdique TEXT,

  mention       TEXT NOT NULL CHECK (mention IN ('REUSSITE','ECHEC')),
  observations  TEXT,

  signee_le     TIMESTAMPTZ NOT NULL DEFAULT now(),
  scellement    TEXT NOT NULL,                    -- SHA-256 des données + secret serveur
  annulee       BOOLEAN NOT NULL DEFAULT FALSE,   -- annulation tracée, jamais suppression
  motif_annulation TEXT,

  UNIQUE (etudiant_id, module_code, tentative)
);
CREATE INDEX idx_eval_etu ON evaluations(etudiant_id) WHERE NOT annulee;
CREATE INDEX idx_eval_mod ON evaluations(module_code) WHERE NOT annulee;

-- 🔒 Aucune modification d'une évaluation signée (sauf annulation tracée)
CREATE OR REPLACE FUNCTION eval_immuable() RETURNS TRIGGER AS $$
BEGIN
  IF OLD.annulee = FALSE AND NEW.annulee = TRUE THEN
    RETURN NEW;                                   -- seule mutation permise : annuler
  END IF;
  RAISE EXCEPTION 'Une évaluation signée est immuable. Créez une nouvelle tentative.';
END; $$ LANGUAGE plpgsql;

CREATE TRIGGER trg_eval_immuable BEFORE UPDATE ON evaluations
  FOR EACH ROW EXECUTE FUNCTION eval_immuable();

-- ── CERTIFICATS / DIPLÔMES ─────────────────────────────────────
CREATE TABLE certificats (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  numero        TEXT UNIQUE NOT NULL,             -- CFPH-ELM-2026-0142
  etudiant_id   UUID NOT NULL REFERENCES etudiants(id),
  filiere       TEXT NOT NULL,
  delivre_par   UUID NOT NULL REFERENCES utilisateurs(id),
  delivre_le    TIMESTAMPTZ NOT NULL DEFAULT now(),
  modules_valides JSONB NOT NULL,                 -- snapshot des 26 mentions
  total_heures  SMALLINT NOT NULL,
  scellement    TEXT NOT NULL,                    -- hash vérifiable
  revoque       BOOLEAN NOT NULL DEFAULT FALSE,
  motif_revocation TEXT
);
CREATE INDEX idx_cert_num ON certificats(numero);

-- ── JOURNAL D'AUDIT (traçabilité) ──────────────────────────────
CREATE TABLE journal (
  id            BIGSERIAL PRIMARY KEY,
  utilisateur_id UUID REFERENCES utilisateurs(id),
  action        TEXT NOT NULL,                    -- eval.create, cert.deliver...
  cible         TEXT,
  donnees       JSONB,
  ip            INET,
  horodatage    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_journal_date ON journal(horodatage DESC);

-- ── VUE : dossier d'un étudiant ────────────────────────────────
CREATE VIEW v_dossier AS
SELECT e.id AS etudiant_id, e.matricule, e.filiere,
       m.code, m.titre, m.heures, m.type_objectif,
       ev.mention, ev.points_obtenus, ev.criteres_valides,
       ev.tentative, ev.date_epreuve, ev.verdique
FROM etudiants e
CROSS JOIN modules m
LEFT JOIN LATERAL (
  SELECT * FROM evaluations x
  WHERE x.etudiant_id = e.id AND x.module_code = m.code AND NOT x.annulee
  ORDER BY (x.mention = 'REUSSITE') DESC, x.tentative DESC
  LIMIT 1
) ev ON TRUE
WHERE m.filiere = e.filiere AND m.actif;

-- ── VUE : éligibilité au diplôme ───────────────────────────────
CREATE VIEW v_eligibilite AS
SELECT etudiant_id, matricule, filiere,
       COUNT(*) FILTER (WHERE mention = 'REUSSITE') AS modules_reussis,
       COUNT(*)                                     AS modules_requis,
       COUNT(*) FILTER (WHERE mention = 'REUSSITE') = COUNT(*) AS eligible
FROM v_dossier
GROUP BY etudiant_id, matricule, filiere;
