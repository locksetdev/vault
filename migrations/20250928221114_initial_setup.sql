--
-- Name: data_encryption_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.data_encryption_keys (
    id integer NOT NULL,
    key_id text NOT NULL,
    kek_id integer NOT NULL,
    encrypted_key text NOT NULL,
    algo text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: data_encryption_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.data_encryption_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: data_encryption_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.data_encryption_keys_id_seq OWNED BY public.data_encryption_keys.id;


--
-- Name: key_encryption_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_encryption_keys (
    id integer NOT NULL,
    kms_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: key_encryption_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.key_encryption_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: key_encryption_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.key_encryption_keys_id_seq OWNED BY public.key_encryption_keys.id;


--
-- Name: secret_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_versions (
    id integer NOT NULL,
    secret_id integer NOT NULL,
    version_tag text NOT NULL,
    sha256sum text,
    encrypted_secret text NOT NULL,
    dek_id integer NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    expire_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);


--
-- Name: secret_versions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.secret_versions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: secret_versions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.secret_versions_id_seq OWNED BY public.secret_versions.id;


--
-- Name: secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secrets (
    id integer NOT NULL,
    name text NOT NULL,
    vault_connection_id integer,
    current_version text,
    previous_version text,
    expire_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: secrets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.secrets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: secrets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.secrets_id_seq OWNED BY public.secrets.id;


--
-- Name: vault_connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vault_connections (
    id integer NOT NULL,
    public_id text NOT NULL,
    integration_type text NOT NULL,
    encrypted_config text NOT NULL,
    dek_id integer NOT NULL,
    ttl integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    sha256sum text NOT NULL
);


--
-- Name: vault_connections_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vault_connections_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vault_connections_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vault_connections_id_seq OWNED BY public.vault_connections.id;


--
-- Name: data_encryption_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_encryption_keys ALTER COLUMN id SET DEFAULT nextval('public.data_encryption_keys_id_seq'::regclass);


--
-- Name: key_encryption_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_encryption_keys ALTER COLUMN id SET DEFAULT nextval('public.key_encryption_keys_id_seq'::regclass);


--
-- Name: secret_versions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions ALTER COLUMN id SET DEFAULT nextval('public.secret_versions_id_seq'::regclass);


--
-- Name: secrets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets ALTER COLUMN id SET DEFAULT nextval('public.secrets_id_seq'::regclass);


--
-- Name: vault_connections id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vault_connections ALTER COLUMN id SET DEFAULT nextval('public.vault_connections_id_seq'::regclass);


--
-- Name: data_encryption_keys data_encryption_keys_key_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_encryption_keys
    ADD CONSTRAINT data_encryption_keys_key_id_key UNIQUE (key_id);


--
-- Name: data_encryption_keys data_encryption_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_encryption_keys
    ADD CONSTRAINT data_encryption_keys_pkey PRIMARY KEY (id);


--
-- Name: key_encryption_keys key_encryption_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_encryption_keys
    ADD CONSTRAINT key_encryption_keys_pkey PRIMARY KEY (id);


--
-- Name: secret_versions secret_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_pkey PRIMARY KEY (id);


--
-- Name: secret_versions secret_versions_secret_id_version_tag_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_secret_id_version_tag_key UNIQUE (secret_id, version_tag);


--
-- Name: secrets secrets_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_name_key UNIQUE (name);


--
-- Name: secrets secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);


--
-- Name: vault_connections vault_connections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vault_connections
    ADD CONSTRAINT vault_connections_pkey PRIMARY KEY (id);


--
-- Name: vault_connections vault_connections_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vault_connections
    ADD CONSTRAINT vault_connections_public_id_key UNIQUE (public_id);


--
-- Name: idx_data_encryption_keys_kek_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_data_encryption_keys_kek_id ON public.data_encryption_keys USING btree (kek_id);


--
-- Name: idx_secret_versions_created_at_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_versions_created_at_desc ON public.secret_versions USING btree (created_at DESC);


--
-- Name: idx_secret_versions_dek_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_versions_dek_id ON public.secret_versions USING btree (dek_id);


--
-- Name: idx_secret_versions_secret_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_versions_secret_id ON public.secret_versions USING btree (secret_id);


--
-- Name: idx_secrets_created_at_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_created_at_desc ON public.secrets USING btree (created_at DESC);


--
-- Name: idx_secrets_expire_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_expire_at ON public.secrets USING btree (expire_at);


--
-- Name: idx_vault_connections_dek_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vault_connections_dek_id ON public.vault_connections USING btree (dek_id);


--
-- Name: idx_vault_connections_integration_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vault_connections_integration_type ON public.vault_connections USING btree (integration_type);


--
-- Name: data_encryption_keys data_encryption_keys_kek_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_encryption_keys
    ADD CONSTRAINT data_encryption_keys_kek_id_fkey FOREIGN KEY (kek_id) REFERENCES public.key_encryption_keys(id) ON DELETE RESTRICT;


--
-- Name: secret_versions secret_versions_dek_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_dek_id_fkey FOREIGN KEY (dek_id) REFERENCES public.data_encryption_keys(id) ON DELETE RESTRICT;


--
-- Name: secret_versions secret_versions_secret_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_secret_id_fkey FOREIGN KEY (secret_id) REFERENCES public.secrets(id) ON DELETE CASCADE;


--
-- Name: secrets secrets_vault_connection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_vault_connection_id_fkey FOREIGN KEY (vault_connection_id) REFERENCES public.vault_connections(id) ON DELETE SET NULL;


--
-- Name: vault_connections vault_connections_dek_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vault_connections
    ADD CONSTRAINT vault_connections_dek_id_fkey FOREIGN KEY (dek_id) REFERENCES public.data_encryption_keys(id) ON DELETE RESTRICT;

