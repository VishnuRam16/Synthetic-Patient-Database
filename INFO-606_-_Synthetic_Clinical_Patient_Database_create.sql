-- Created by Vertabelo (http://vertabelo.com)
-- Last modification date: 2024-01-17 23:09:54.48

-- tables
-- Table: MITRE_PATIENT
CREATE TABLE MITRE_PATIENT (
    PATIENT_ID varchar2(255)  NULL,
    BIRTHDATE date  NULL,
    DEATHDATE date  NULL,
    SSN varchar2(50)  NULL,
    DRIVERS varchar2(50)  NULL,
    PASSPORT varchar2(50)  NULL,
    PREFIX varchar2(50)  NULL,
    FIRST_NAME varchar2(50)  NULL,
    LAST_NAME varchar2(50)  NULL,
    SUFFIX varchar2(50)  NULL,
    MAIDEN_NAME varchar2(50)  NULL,
    MARITAL_STATUS char(1)  NULL,
    RACE varchar2(50)  NULL,
    ETHNICITY varchar2(50)  NULL,
    GENDER char(1)  NULL,
    BIRTH_PLACE varchar2(255)  NULL,
    ADDRESS varchar2(255)  NULL,
    CITY varchar2(50)  NULL,
    STATE varchar2(50)  NULL,
    COUNTY varchar2(50)  NULL,
    ZIP varchar2(10)  NULL,
    LAT number(20,17)  NULL,
    LON number(20,17)  NULL,
    HEALTHCARE_EXPENSES number(15,2)  NULL,
    HEALTHCARE_COVERAGE number(15,2)  NULL
) ;

-- Table: MITRE_PATIENT_ALLERGY
CREATE TABLE MITRE_PATIENT_ALLERGY (
    ALLERGY_START date  NULL,
    ALLERGY_STOP date  NULL,
    PATIENT_ID varchar2(255)  NULL,
    ENCOUNTER_ID varchar2(255)  NULL,
    ALLERGY_CODE varchar2(20)  NULL,
    ALLERGY_DESCRIPTION varchar2(255)  NULL
) ;

-- Table: MITRE_PATIENT_IMAGING_STUDY
CREATE TABLE MITRE_PATIENT_IMAGING_STUDY (
    IMAGING_STUDY_ID varchar2(255)  NULL,
    IMAGING_STUDY_DATE date  NULL,
    PATIENT_ID varchar2(255)  NULL,
    ENCOUNTER_ID varchar2(255)  NULL,
    BODYSITE_CODE varchar2(20)  NULL,
    BODYSITE_DESCRIPTION varchar2(255)  NULL,
    MODALITY_CODE char(2)  NULL,
    MODALITY_DESCRIPTION varchar2(255)  NULL,
    SOP_CODE varchar2(50)  NULL,
    SOP_DESCRIPTION varchar2(255)  NULL
) ;

-- Table: MITRE_PATIENT_IMMUNIZATION
CREATE TABLE MITRE_PATIENT_IMMUNIZATION (
    IMMUNIZATION_DATE date  NULL,
    PATIENT_ID varchar2(255)  NULL,
    ENCOUNTER_ID varchar2(255)  NULL,
    IMMUNIZATION_CODE number(5)  NULL,
    IMMUNIZATION_DESCRIPTION varchar2(255)  NULL,
    BASE_COST number(15,2)  NULL
) ;

-- Table: MITRE_PATIENT_MEDICATION
CREATE TABLE MITRE_PATIENT_MEDICATION (
    MEDICATION_START date  NULL,
    MEDICATION_STOP date  NULL,
    PATIENT_ID varchar2(255)  NULL,
    PAYER_ID varchar2(255)  NULL,
    ENCOUNTER_ID varchar2(255)  NULL,
    MEDICATION_CODE varchar2(20)  NULL,
    MEDICATION_DESCRIPTION varchar2(255)  NULL,
    BASE_COST number(15,2)  NULL,
    PAYER_COVERAGE number(15,2)  NULL,
    MEDICATION_DISPENSES number(5)  NULL,
    TOTAL_COST number(15,2)  NULL,
    REASON_CODE varchar2(20)  NULL,
    REASON_DESCRIPTION varchar2(255)  NULL
) ;

-- Table: MITRE_PATIENT_PROCEDURE
CREATE TABLE MITRE_PATIENT_PROCEDURE (
    PROCEDURE_DATE date  NULL,
    PATIENT_ID varchar2(255)  NULL,
    ENCOUNTER_ID varchar2(255)  NULL,
    PROCEDURE_CODE varchar2(20)  NULL,
    PROCEDURE_DESCRIPTION varchar2(255)  NULL,
    BASE_COST number(15,2)  NULL,
    REASON_CODE varchar2(20)  NULL,
    REASON_DESCRIPTION varchar2(255)  NULL
) ;

-- Table: NITRE_ALLERGY
CREATE TABLE NITRE_ALLERGY (
    ALLERGY_CODE varchar2(20)  NOT NULL,
    ALLERGY_DESCRIPTION varchar2(255)  NULL,
    CONSTRAINT NITRE_ALLERGY_DESCRIPTION_UK UNIQUE (ALLERGY_DESCRIPTION),
    CONSTRAINT NITRE_ALLERGY_pk PRIMARY KEY (ALLERGY_CODE)
) ;

-- Table: NITRE_BODYSITE
CREATE TABLE NITRE_BODYSITE (
    BODYSITE_CODE varchar2(10)  NOT NULL,
    BODYSITE_DESCRIPTION varchar2(50)  NOT NULL,
    CONSTRAINT NITRE_BODYSITE_DESC_UK UNIQUE (BODYSITE_DESCRIPTION),
    CONSTRAINT NITRE_BODYSITE_pk PRIMARY KEY (BODYSITE_CODE)
) ;

-- Table: NITRE_CITY
CREATE TABLE NITRE_CITY (
    COUNTRY_ID number(5)  NOT NULL,
    STATE_ID number(5)  NOT NULL,
    CITY_ID number(5)  NOT NULL,
    CITY_NAME varchar2(50)  NOT NULL,
    COUNTY_ID number(5)  NULL,
    CONSTRAINT NITRE_CITY_NAME_UK UNIQUE (COUNTRY_ID, STATE_ID, CITY_NAME),
    CONSTRAINT NITRE_CITY_pk PRIMARY KEY (COUNTRY_ID,STATE_ID,CITY_ID)
) ;

-- Table: NITRE_COUNTRY
CREATE TABLE NITRE_COUNTRY (
    COUNTRY_ID number(5)  NOT NULL,
    COUNTRY_NAME char(2)  NOT NULL,
    CONSTRAINT NITRE_COUNTRY_NAME_UK UNIQUE (COUNTRY_NAME),
    CONSTRAINT NITRE_COUNTRY_pk PRIMARY KEY (COUNTRY_ID)
) ;

-- Table: NITRE_COUNTY
CREATE TABLE NITRE_COUNTY (
    COUNTRY_ID number(5)  NOT NULL,
    STATE_ID number(5)  NOT NULL,
    COUNTY_ID number(5)  NOT NULL,
    COUNTY_NAME varchar2(50)  NOT NULL,
    CONSTRAINT NITRE_COUNTY_NAME_UK UNIQUE (COUNTRY_ID, STATE_ID, COUNTY_NAME),
    CONSTRAINT NITRE_COUNTY_pk PRIMARY KEY (COUNTRY_ID,STATE_ID,COUNTY_ID)
) ;

-- Table: NITRE_ETHNICITY
CREATE TABLE NITRE_ETHNICITY (
    ETHNICITY_ID number(5)  NOT NULL,
    ETHNICITY_DESCRIPTION varchar2(50)  NOT NULL,
    CONSTRAINT NITRE_ETHNICITY_DESC_UK UNIQUE (ETHNICITY_DESCRIPTION),
    CONSTRAINT NITRE_ETHNICITY_pk PRIMARY KEY (ETHNICITY_ID)
) ;

-- Table: NITRE_GENDER
CREATE TABLE NITRE_GENDER (
    GENDER_ID char(1)  NOT NULL,
    GENDER_DESCRIPTION varchar2(50)  NOT NULL,
    CONSTRAINT NITRE_GENDER_DESC_UK UNIQUE (GENDER_DESCRIPTION),
    CONSTRAINT NITRE_GENDER_pk PRIMARY KEY (GENDER_ID)
) ;

-- Table: NITRE_IMMUNIZATION
CREATE TABLE NITRE_IMMUNIZATION (
    IMMUNIZATION_CODE varchar2(5)  NOT NULL,
    IMMUNIZATION_DESCRIPTION varchar2(50)  NOT NULL,
    CONSTRAINT NITRE_IMMUNIZATION_DESC_UK UNIQUE (IMMUNIZATION_DESCRIPTION),
    CONSTRAINT NITRE_IMMUNIZATION_pk PRIMARY KEY (IMMUNIZATION_CODE)
) ;

-- Table: NITRE_MARITAL_STATUS
CREATE TABLE NITRE_MARITAL_STATUS (
    MARITAL_STATUS_ID char(1)  NOT NULL,
    MARITAL_STATUS_DESCRIPTION varchar2(50)  NOT NULL,
    CONSTRAINT NITRE_MARITAL_STATUS_DESC_UK UNIQUE (MARITAL_STATUS_DESCRIPTION),
    CONSTRAINT NITRE_MARITAL_STATUS_pk PRIMARY KEY (MARITAL_STATUS_ID)
) ;

-- Table: NITRE_MEDICATION
CREATE TABLE NITRE_MEDICATION (
    MEDICATION_CODE varchar2(20)  NOT NULL,
    MEDICATION_DESCRIPTION varchar2(150)  NOT NULL,
    CONSTRAINT NITRE_MEDICATION_DESC_UK UNIQUE (MEDICATION_DESCRIPTION),
    CONSTRAINT NITRE_MEDICATION_pk PRIMARY KEY (MEDICATION_CODE)
) ;

-- Table: NITRE_MODALITY
CREATE TABLE NITRE_MODALITY (
    MODALITY_CODE char(2)  NOT NULL,
    MODALITY_DESCRIPTION varchar2(50)  NOT NULL,
    CONSTRAINT NITRE_MODALITY_DESC_UK UNIQUE (MODALITY_DESCRIPTION),
    CONSTRAINT NITRE_MODALITY_pk PRIMARY KEY (MODALITY_CODE)
) ;

-- Table: NITRE_PATIENT
CREATE TABLE NITRE_PATIENT (
    PATIENT_ID varchar2(255)  NOT NULL,
    BIRTHDATE date  NOT NULL,
    DEATHDATE date  NULL,
    SSN varchar2(50)  NOT NULL,
    DRIVERS varchar2(50)  NULL,
    PASSPORT varchar2(50)  NULL,
    PREFIX varchar2(50)  NULL,
    FIRST_NAME varchar2(50)  NOT NULL,
    LAST_NAME varchar2(50)  NOT NULL,
    SUFFIX varchar2(50)  NULL,
    MAIDEN_NAME varchar2(50)  NULL,
    MARITAL_STATUS_ID char(1)  NOT NULL,
    RACE_ID number(5)  NOT NULL,
    ETHNICITY_ID number(5)  NOT NULL,
    GENDER_ID char(1)  NOT NULL,
    HEALTHCARE_EXPENSES number(15,2)  NOT NULL,
    HEALTHCARE_COVERAGE number(15,2)  NOT NULL,
    BIRTH_PLACE_COUNTRY_ID number(5)  NOT NULL,
    BIRTH_PLACE_STATE_ID number(5)  NOT NULL,
    BIRTH_PLACE_CITY_ID number(5)  NOT NULL,
    ADDRESS varchar2(255)  NOT NULL,
    ZIP varchar2(10)  NULL,
    LIVING_PLACE_COUNTRY_ID number(5)  NOT NULL,
    LIVING_PLACE_STATE_ID number(5)  NOT NULL,
    LIVING_PLACE_CITY_ID number(5)  NOT NULL,
    CONSTRAINT NITRE_PATIENT_pk PRIMARY KEY (PATIENT_ID)
) ;

-- Table: NITRE_PATIENT_ALLERGY
CREATE TABLE NITRE_PATIENT_ALLERGY (
    PATIENT_ID varchar2(255)  NOT NULL,
    ALLERGY_CODE varchar2(20)  NOT NULL,
    ALLERGY_START date  NOT NULL,
    ALLERGY_STOP date  NULL,
    CONSTRAINT NITRE_PATIENT_ALLERGY_pk PRIMARY KEY (PATIENT_ID,ALLERGY_CODE,ALLERGY_START)
) ;

-- Table: NITRE_PATIENT_IMAGING_STUDY
CREATE TABLE NITRE_PATIENT_IMAGING_STUDY (
    IMAGING_STUDY_ID varchar2(255)  NOT NULL,
    IMAGING_STUDY_DATE date  NOT NULL,
    PATIENT_ID varchar2(255)  NOT NULL,
    BODYSITE_CODE varchar2(10)  NOT NULL,
    MODALITY_CODE char(2)  NOT NULL,
    SOP_CODE varchar2(30)  NOT NULL,
    CONSTRAINT NITRE_PATIENT_IMAGING_STUDY_pk PRIMARY KEY (IMAGING_STUDY_ID)
) ;

-- Table: NITRE_PATIENT_IMMUNIZATION
CREATE TABLE NITRE_PATIENT_IMMUNIZATION (
    PATIENT_ID varchar2(255)  NOT NULL,
    IMMUNIZATION_CODE varchar2(5)  NOT NULL,
    IMMUNIZATION_DATE date  NOT NULL,
    BASE_COST number(15,2)  NULL,
    CONSTRAINT NITRE_PATIENT_IMMUNIZATION_pk PRIMARY KEY (PATIENT_ID,IMMUNIZATION_CODE,IMMUNIZATION_DATE)
) ;

-- Table: NITRE_PATIENT_MEDICATION
CREATE TABLE NITRE_PATIENT_MEDICATION (
    PATIENT_ID varchar2(255)  NOT NULL,
    MEDICATION_CODE varchar2(20)  NOT NULL,
    MEDICATION_START date  NOT NULL,
    MEDICATION_STOP date  NULL,
    BASE_COST number(15,2)  NULL,
    PAYER_COVERAGE number(15,2)  NULL,
    MEDICATION_DISPENSES number(5)  NULL,
    TOTAL_COST number(15,2)  NULL,
    REASON_CODE varchar2(20)  NULL
) ;

-- Table: NITRE_PATIENT_PROCEDURE
CREATE TABLE NITRE_PATIENT_PROCEDURE (
    PATIENT_ID varchar2(255)  NOT NULL,
    PROCEDURE_CODE varchar2(20)  NOT NULL,
    PROCEDURE_DATE date  NOT NULL,
    BASE_COST number(15,2)  NULL,
    REASON_CODE varchar2(20)  NULL,
    CONSTRAINT NITRE_PATIENT_PROCEDURE_pk PRIMARY KEY (PATIENT_ID,PROCEDURE_CODE,PROCEDURE_DATE)
) ;

-- Table: NITRE_PROCEDURE
CREATE TABLE NITRE_PROCEDURE (
    PROCEDURE_CODE varchar2(20)  NOT NULL,
    PROCEDURE_DESCRIPTION varchar2(150)  NOT NULL,
    CONSTRAINT NITRE_PROCEDURE_DESC_UK UNIQUE (PROCEDURE_DESCRIPTION),
    CONSTRAINT NITRE_PROCEDURE_pk PRIMARY KEY (PROCEDURE_CODE)
) ;

-- Table: NITRE_RACE
CREATE TABLE NITRE_RACE (
    RACE_ID number(5)  NOT NULL,
    RACE_DESCRIPTION varchar2(50)  NOT NULL,
    CONSTRAINT NITRE_RACE_DESC_UK UNIQUE (RACE_DESCRIPTION),
    CONSTRAINT NITRE_RACE_pk PRIMARY KEY (RACE_ID)
) ;

-- Table: NITRE_REASON
CREATE TABLE NITRE_REASON (
    REASON_CODE varchar2(20)  NOT NULL,
    REASON_DESCRIPTION varchar2(100)  NOT NULL,
    CONSTRAINT NITRE_REASON_DESC_UK UNIQUE (REASON_DESCRIPTION),
    CONSTRAINT NITRE_REASON_pk PRIMARY KEY (REASON_CODE)
) ;

-- Table: NITRE_SOP
CREATE TABLE NITRE_SOP (
    SOP_CODE varchar2(30)  NOT NULL,
    SOP_DESCRIPTION varchar2(50)  NOT NULL,
    CONSTRAINT NITRE_SOP_DESC_UK UNIQUE (SOP_DESCRIPTION),
    CONSTRAINT NITRE_SOP_pk PRIMARY KEY (SOP_CODE)
) ;

-- Table: NITRE_STATE
CREATE TABLE NITRE_STATE (
    COUNTRY_ID number(5)  NOT NULL,
    STATE_ID number(5)  NOT NULL,
    STATE_NAME varchar2(100)  NOT NULL,
    CONSTRAINT NITRE_STATE_NAME_UK UNIQUE (COUNTRY_ID, STATE_NAME),
    CONSTRAINT NITRE_STATE_pk PRIMARY KEY (COUNTRY_ID,STATE_ID)
) ;

-- foreign keys
-- Reference: NITRE_ALLERGY_PATIENT_FK (table: NITRE_PATIENT_ALLERGY)
ALTER TABLE NITRE_PATIENT_ALLERGY ADD CONSTRAINT NITRE_ALLERGY_PATIENT_FK
    FOREIGN KEY (PATIENT_ID)
    REFERENCES NITRE_PATIENT (PATIENT_ID);

-- Reference: NITRE_CITY_COUNTY_FK (table: NITRE_CITY)
ALTER TABLE NITRE_CITY ADD CONSTRAINT NITRE_CITY_COUNTY_FK
    FOREIGN KEY (COUNTRY_ID,STATE_ID,COUNTY_ID)
    REFERENCES NITRE_COUNTY (COUNTRY_ID,STATE_ID,COUNTY_ID);

-- Reference: NITRE_CITY_Z_STATE (table: NITRE_CITY)
ALTER TABLE NITRE_CITY ADD CONSTRAINT NITRE_CITY_Z_STATE
    FOREIGN KEY (COUNTRY_ID,STATE_ID)
    REFERENCES NITRE_STATE (COUNTRY_ID,STATE_ID);

-- Reference: NITRE_COUNTY_STATE_FK (table: NITRE_COUNTY)
ALTER TABLE NITRE_COUNTY ADD CONSTRAINT NITRE_COUNTY_STATE_FK
    FOREIGN KEY (COUNTRY_ID,STATE_ID)
    REFERENCES NITRE_STATE (COUNTRY_ID,STATE_ID);

-- Reference: NITRE_IMAGING_STUDY_PATIENT_FK (table: NITRE_PATIENT_IMAGING_STUDY)
ALTER TABLE NITRE_PATIENT_IMAGING_STUDY ADD CONSTRAINT NITRE_IMAGING_STUDY_PATIENT_FK
    FOREIGN KEY (PATIENT_ID)
    REFERENCES NITRE_PATIENT (PATIENT_ID);

-- Reference: NITRE_IMMUNIZATION_PATIENT_FK (table: NITRE_PATIENT_IMMUNIZATION)
ALTER TABLE NITRE_PATIENT_IMMUNIZATION ADD CONSTRAINT NITRE_IMMUNIZATION_PATIENT_FK
    FOREIGN KEY (PATIENT_ID)
    REFERENCES NITRE_PATIENT (PATIENT_ID);

-- Reference: NITRE_MEDICATION_PATIENT_FK (table: NITRE_PATIENT_MEDICATION)
ALTER TABLE NITRE_PATIENT_MEDICATION ADD CONSTRAINT NITRE_MEDICATION_PATIENT_FK
    FOREIGN KEY (PATIENT_ID)
    REFERENCES NITRE_PATIENT (PATIENT_ID);

-- Reference: NITRE_PATIENT_ALLERGY_FK (table: NITRE_PATIENT_ALLERGY)
ALTER TABLE NITRE_PATIENT_ALLERGY ADD CONSTRAINT NITRE_PATIENT_ALLERGY_FK
    FOREIGN KEY (ALLERGY_CODE)
    REFERENCES NITRE_ALLERGY (ALLERGY_CODE);

-- Reference: NITRE_PATIENT_BIRTH_PLACE_FK (table: NITRE_PATIENT)
ALTER TABLE NITRE_PATIENT ADD CONSTRAINT NITRE_PATIENT_BIRTH_PLACE_FK
    FOREIGN KEY (BIRTH_PLACE_COUNTRY_ID,BIRTH_PLACE_STATE_ID,BIRTH_PLACE_CITY_ID)
    REFERENCES NITRE_CITY (COUNTRY_ID,STATE_ID,CITY_ID);

-- Reference: NITRE_PATIENT_BODYSITE_FK (table: NITRE_PATIENT_IMAGING_STUDY)
ALTER TABLE NITRE_PATIENT_IMAGING_STUDY ADD CONSTRAINT NITRE_PATIENT_BODYSITE_FK
    FOREIGN KEY (BODYSITE_CODE)
    REFERENCES NITRE_BODYSITE (BODYSITE_CODE);

-- Reference: NITRE_PATIENT_ETHNICITY_FK (table: NITRE_PATIENT)
ALTER TABLE NITRE_PATIENT ADD CONSTRAINT NITRE_PATIENT_ETHNICITY_FK
    FOREIGN KEY (ETHNICITY_ID)
    REFERENCES NITRE_ETHNICITY (ETHNICITY_ID);

-- Reference: NITRE_PATIENT_GENDER_FK (table: NITRE_PATIENT)
ALTER TABLE NITRE_PATIENT ADD CONSTRAINT NITRE_PATIENT_GENDER_FK
    FOREIGN KEY (GENDER_ID)
    REFERENCES NITRE_GENDER (GENDER_ID);

-- Reference: NITRE_PATIENT_IMMUNIZATION_FK (table: NITRE_PATIENT_IMMUNIZATION)
ALTER TABLE NITRE_PATIENT_IMMUNIZATION ADD CONSTRAINT NITRE_PATIENT_IMMUNIZATION_FK
    FOREIGN KEY (IMMUNIZATION_CODE)
    REFERENCES NITRE_IMMUNIZATION (IMMUNIZATION_CODE);

-- Reference: NITRE_PATIENT_LIVING_PLACE_FK (table: NITRE_PATIENT)
ALTER TABLE NITRE_PATIENT ADD CONSTRAINT NITRE_PATIENT_LIVING_PLACE_FK
    FOREIGN KEY (LIVING_PLACE_COUNTRY_ID,LIVING_PLACE_STATE_ID,LIVING_PLACE_CITY_ID)
    REFERENCES NITRE_CITY (COUNTRY_ID,STATE_ID,CITY_ID);

-- Reference: NITRE_PATIENT_MARITALSTATUS_FK (table: NITRE_PATIENT)
ALTER TABLE NITRE_PATIENT ADD CONSTRAINT NITRE_PATIENT_MARITALSTATUS_FK
    FOREIGN KEY (MARITAL_STATUS_ID)
    REFERENCES NITRE_MARITAL_STATUS (MARITAL_STATUS_ID);

-- Reference: NITRE_PATIENT_MEDICATION_FK (table: NITRE_PATIENT_MEDICATION)
ALTER TABLE NITRE_PATIENT_MEDICATION ADD CONSTRAINT NITRE_PATIENT_MEDICATION_FK
    FOREIGN KEY (MEDICATION_CODE)
    REFERENCES NITRE_MEDICATION (MEDICATION_CODE);

-- Reference: NITRE_PATIENT_MEDIC_REASON_FK (table: NITRE_PATIENT_MEDICATION)
ALTER TABLE NITRE_PATIENT_MEDICATION ADD CONSTRAINT NITRE_PATIENT_MEDIC_REASON_FK
    FOREIGN KEY (REASON_CODE)
    REFERENCES NITRE_REASON (REASON_CODE);

-- Reference: NITRE_PATIENT_MODALITY_FK (table: NITRE_PATIENT_IMAGING_STUDY)
ALTER TABLE NITRE_PATIENT_IMAGING_STUDY ADD CONSTRAINT NITRE_PATIENT_MODALITY_FK
    FOREIGN KEY (MODALITY_CODE)
    REFERENCES NITRE_MODALITY (MODALITY_CODE);

-- Reference: NITRE_PATIENT_PROCEDURE_FK (table: NITRE_PATIENT_PROCEDURE)
ALTER TABLE NITRE_PATIENT_PROCEDURE ADD CONSTRAINT NITRE_PATIENT_PROCEDURE_FK
    FOREIGN KEY (PROCEDURE_CODE)
    REFERENCES NITRE_PROCEDURE (PROCEDURE_CODE);

-- Reference: NITRE_PATIENT_PROC_REASON_FK (table: NITRE_PATIENT_PROCEDURE)
ALTER TABLE NITRE_PATIENT_PROCEDURE ADD CONSTRAINT NITRE_PATIENT_PROC_REASON_FK
    FOREIGN KEY (REASON_CODE)
    REFERENCES NITRE_REASON (REASON_CODE);

-- Reference: NITRE_PATIENT_RACE_FK (table: NITRE_PATIENT)
ALTER TABLE NITRE_PATIENT ADD CONSTRAINT NITRE_PATIENT_RACE_FK
    FOREIGN KEY (RACE_ID)
    REFERENCES NITRE_RACE (RACE_ID);

-- Reference: NITRE_PATIENT_SOP_FK (table: NITRE_PATIENT_IMAGING_STUDY)
ALTER TABLE NITRE_PATIENT_IMAGING_STUDY ADD CONSTRAINT NITRE_PATIENT_SOP_FK
    FOREIGN KEY (SOP_CODE)
    REFERENCES NITRE_SOP (SOP_CODE);

-- Reference: NITRE_PROCEDURE_PATIENT_FK (table: NITRE_PATIENT_PROCEDURE)
ALTER TABLE NITRE_PATIENT_PROCEDURE ADD CONSTRAINT NITRE_PROCEDURE_PATIENT_FK
    FOREIGN KEY (PATIENT_ID)
    REFERENCES NITRE_PATIENT (PATIENT_ID);

-- Reference: NITRE_STATE_COUTRY_FK (table: NITRE_STATE)
ALTER TABLE NITRE_STATE ADD CONSTRAINT NITRE_STATE_COUTRY_FK
    FOREIGN KEY (COUNTRY_ID)
    REFERENCES NITRE_COUNTRY (COUNTRY_ID);

-- End of file.

