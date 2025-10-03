-- =================================================================
-- Table Definitions with Inline Constraints
-- =================================================================

CREATE TABLE "key_encryption_keys" (
   "id" serial PRIMARY KEY NOT NULL,
   "kms_key" text NOT NULL,
   "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE "data_encryption_keys" (
    "id" serial PRIMARY KEY NOT NULL,
    "key_id" text NOT NULL,
    "kek_id" integer NOT NULL,
    "encrypted_key" text NOT NULL,
    "algo" text NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT "data_encryption_keys_key_id_key" UNIQUE("key_id")
);

CREATE TABLE "vault_connections" (
    "id" serial PRIMARY KEY NOT NULL,
    "public_id" text NOT NULL,
    "integration_type" text NOT NULL,
    "encrypted_config" text NOT NULL,
    "sha256sum" text NOT NULL,
    "dek_id" integer NOT NULL,
    "ttl" integer,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT "vault_connections_public_id_key" UNIQUE("public_id")
);

CREATE TABLE "secrets" (
    "id" serial PRIMARY KEY NOT NULL,
    "name" text NOT NULL,
    "vault_connection_id" integer,
    "current_version" text,
    "previous_version" text,
    "expire_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT "secrets_name_key" UNIQUE("name")
);

CREATE TABLE "secret_versions" (
    "id" serial PRIMARY KEY NOT NULL,
    "secret_id" integer NOT NULL,
    "version_tag" text NOT NULL,
    "sha256sum" text NOT NULL,
    "encrypted_secret" text NOT NULL,
    "dek_id" integer NOT NULL,
    "deleted" boolean DEFAULT false NOT NULL,
    "expire_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
    "deleted_at" timestamp with time zone,
    CONSTRAINT "secret_versions_secret_id_version_tag_key" UNIQUE("secret_id", "version_tag")
);

-- =================================================================
-- Foreign Key Constraints
-- =================================================================

ALTER TABLE "data_encryption_keys" ADD CONSTRAINT "data_encryption_keys_kek_id_fkey" FOREIGN KEY ("kek_id") REFERENCES "public"."key_encryption_keys"("id") ON DELETE restrict ON UPDATE no action;
ALTER TABLE "vault_connections" ADD CONSTRAINT "vault_connections_dek_id_fkey" FOREIGN KEY ("dek_id") REFERENCES "public"."data_encryption_keys"("id") ON DELETE restrict ON UPDATE no action;
ALTER TABLE "secrets" ADD CONSTRAINT "secrets_vault_connection_id_fkey" FOREIGN KEY ("vault_connection_id") REFERENCES "public"."vault_connections"("id") ON DELETE set null ON UPDATE no action;
ALTER TABLE "secret_versions" ADD CONSTRAINT "secret_versions_secret_id_fkey" FOREIGN KEY ("secret_id") REFERENCES "public"."secrets"("id") ON DELETE cascade ON UPDATE no action;
ALTER TABLE "secret_versions" ADD CONSTRAINT "secret_versions_dek_id_fkey" FOREIGN KEY ("dek_id") REFERENCES "public"."data_encryption_keys"("id") ON DELETE restrict ON UPDATE no action;

-- =================================================================
-- Indexes for Performance
-- =================================================================

CREATE INDEX "idx_data_encryption_keys_kek_id" ON "data_encryption_keys" USING btree ("kek_id" int4_ops);
CREATE INDEX "idx_vault_connections_dek_id" ON "vault_connections" USING btree ("dek_id" int4_ops);
CREATE INDEX "idx_secret_versions_dek_id" ON "secret_versions" USING btree ("dek_id" int4_ops);
CREATE INDEX "idx_secret_versions_secret_id" ON "secret_versions" USING btree ("secret_id" int4_ops);
CREATE INDEX "idx_secrets_expire_at" ON "secrets" ("expire_at");
CREATE INDEX "idx_vault_connections_integration_type" ON "vault_connections" ("integration_type");
CREATE INDEX "idx_secrets_created_at_desc" ON "secrets" ("created_at" DESC);
CREATE INDEX "idx_secret_versions_created_at_desc" ON "secret_versions" ("created_at" DESC);