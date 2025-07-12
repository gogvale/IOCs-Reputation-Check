-- IoC definition

CREATE TABLE IoC (
	ioc TEXT NOT NULL,
	ioc_type TEXT NOT NULL,
	vt_detections INTEGER,
	created_at TEXT,
	updated_at TEXT,
	last_seen TEXT,
	CONSTRAINT IoC_PK PRIMARY KEY (ioc)
);