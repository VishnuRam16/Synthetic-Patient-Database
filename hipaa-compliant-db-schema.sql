-- SQL script for NITRE database security enhancements
-- File: nitre_security_enhancements.sql

SET SERVEROUTPUT ON;
SET ECHO ON;

-- Create a new table for audit logging
CREATE TABLE NITRE_AUDIT_LOG (
    LOG_ID NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    TABLE_NAME VARCHAR2(30) NOT NULL,
    OPERATION VARCHAR2(10) NOT NULL,
    USER_ID VARCHAR2(30) NOT NULL,
    TIMESTAMP TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
    OLD_VALUE CLOB,
    NEW_VALUE CLOB
);

-- Add encryption to sensitive columns (if Advanced Security Option is available)
-- If not available, you may need to remove or comment out these lines
ALTER TABLE NITRE_PATIENT MODIFY (
    SSN ENCRYPT USING 'AES256',
    DRIVERS ENCRYPT USING 'AES256',
    PASSPORT ENCRYPT USING 'AES256'
);

-- Create a view for de-identified patient data
CREATE OR REPLACE VIEW NITRE_PATIENT_DEIDENTIFIED AS
SELECT 
    PATIENT_ID,
    EXTRACT(YEAR FROM BIRTHDATE) AS BIRTH_YEAR,
    CASE 
        WHEN DEATHDATE IS NOT NULL THEN 'Deceased'
        ELSE 'Living'
    END AS LIFE_STATUS,
    MARITAL_STATUS_ID,
    RACE_ID,
    ETHNICITY_ID,
    GENDER_ID,
    BIRTH_PLACE_COUNTRY_ID,
    BIRTH_PLACE_STATE_ID,
    LIVING_PLACE_COUNTRY_ID,
    LIVING_PLACE_STATE_ID
FROM NITRE_PATIENT;

-- Create a function to mask sensitive data
CREATE OR REPLACE FUNCTION MASK_DATA(p_data VARCHAR2) RETURN VARCHAR2 IS
BEGIN
    RETURN RPAD('X', LENGTH(p_data), 'X');
END;
/

-- Create a package for security functions
CREATE OR REPLACE PACKAGE NITRE_SECURITY AS
    FUNCTION PATIENT_ACCESS_PREDICATE(schema_name IN VARCHAR2, table_name IN VARCHAR2) 
    RETURN VARCHAR2;
END NITRE_SECURITY;
/

CREATE OR REPLACE PACKAGE BODY NITRE_SECURITY AS
    FUNCTION PATIENT_ACCESS_PREDICATE(schema_name IN VARCHAR2, table_name IN VARCHAR2) 
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN 'SYS_CONTEXT(''USERENV'', ''SESSION_USER'') = ''ADMIN'' OR ' ||
               'PATIENT_ID IN (SELECT PATIENT_ID FROM USER_PATIENTS WHERE USER_ID = SYS_CONTEXT(''USERENV'', ''SESSION_USER''))';
    END PATIENT_ACCESS_PREDICATE;
END NITRE_SECURITY;
/

-- Apply the security policy to the NITRE_PATIENT table
-- Note: Replace 'YOUR_SCHEMA' with your actual schema name
BEGIN
    DBMS_RLS.ADD_POLICY (
        object_schema   => 'YOUR_SCHEMA',
        object_name     => 'NITRE_PATIENT',
        policy_name     => 'PATIENT_ACCESS_POLICY',
        function_schema => 'YOUR_SCHEMA',
        policy_function => 'NITRE_SECURITY.PATIENT_ACCESS_PREDICATE',
        statement_types => 'SELECT, INSERT, UPDATE, DELETE'
    );
END;
/

-- More SQL statements...

-- End of script
EXIT;
