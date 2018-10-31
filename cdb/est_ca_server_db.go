/* Copyright (c) 2018 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * -----------------------------------------------------------
 * func InitDB(filepath string) *sql.DB
 * Call for initializing the database
 * -----------------------------------------------------------
 * func checkErr(err error)
 * Printing general purpose database panic errors
 * ------------------------------------------------------------
 * CA Table Database Utilities
 * ------------------------------------------------------------
 * func CreateCaTable(db *sql.DB)
 * func SearchCaItem(db *sql.DB, caName string) (CaTable, int)
 * func checkCount(rows *sql.Rows) (count int)
 * func StoreCaItem(db *sql.DB, item CaTable)
 * func ReadCaTable(db *sql.DB) []CaTable
 * func ReadCaItem(db *sql.DB, caName string) CaTable
 * -------------------------------------------------------------
 * Certificate Table Database Utilities
 * -------------------------------------------------------------
 * func CreateCertTable(db *sql.DB)
 * func StoreCertItem(db *sql.DB, item CertTable)
 * func ReadCertTable(db *sql.DB) []CertTable
 * --------------------------------------------------------------
 * Enrollment Table Database Utilities
 * --------------------------------------------------------------
 * func CreateEnrollTable(db *.sql.DB)
 * func StoreEnrollItem(db *sql.DB, item EnrollTable)
 * func SearchEnrollItem(db *sql.DB, enrollid string) (EnrollTable, int)
 * func ReadEnrollTable(db *sql.DB) []EnrollTable
 *
 * ---------------------------------------------------------------
 * CRL Table Database Utilities
 * ---------------------------------------------------------------
 * func CreateCrlTable(db *sql.DB)
 * func StoreCrlItem(db *sql.DB, item CrlTable)
 * func ReadCrlTable(db *sql.DB) []CrlTable
 *
 * ---------------------------------------------------------------
 * CA Profile Table Database Utilities
 * ---------------------------------------------------------------
 * func CreateCaProfileTable(db *sql.DB)
 * func StoreCaProfileItem(db *sql.DB, item CaProfileTable)
 * func ReadCaProfileTable(db *sql.DB) []CaProfileTable
 * --------------------------------------------------------------
 *
 *
 */

package cdb

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

type CaTable struct {
	Name        string
	Csr         string
	Cert        string
	Key         string
	Fingerprint string
	FpAlgo      int
	Validity    int
	EnrollCount int //Enrollment count
	Serial      int
}

type CertTable struct {
	EnrollId    string
	Certificate string
	Csr         string
	Validity    int
	Signature   string
	CaName      string
}

type EnrollTable struct {
	EnrollId   string
	Secret     string
	Attributes string
	Status     int
	Role       string
	Ca         string
	CaProfile  string
}

type CrlTable struct {
	Name     string
	Validity int
	Updt     string //Update since last commit
	Time     int    //Last commit time
}

type CaProfileTable struct {
	Name       string
	O          string
	OU         string
	CN         string
	IP         string
	Host       int
	IsCa       int
	Pathlength int
	Validity   int
}

func InitDB(filepath string) *sql.DB {
	db, err := sql.Open("sqlite3", filepath)
	checkErr(err)
	if db == nil {
		panic("db nil")
	}
	return db
}

/* printing database errors */
func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

/* CA Table create if not created | checks if an entry with same CA name is already present | if present validates for csr (TODO: this workflow)*/
func CreateCaTable(db *sql.DB) {
	sql_table := `
        CREATE TABLE IF NOT EXISTS ca_data(
                Name TEXT NOT NULL PRIMARY KEY,
                Csr TEXT,
				Cert TEXT,
                Key TEXT,
                Fingerprint TEXT,
                FpAlgo INT,
                Validity INT,
                EnrollCount INT,
				Serial INT
        )`
	_, err := db.Exec(sql_table)
	checkErr(err)
}

/* search a row in CA table by CA name */
func SearchCaItem(db *sql.DB, caName string) (CaTable, int) {
	result := CaTable{"", "", "", "", "", 0, 0, 0, 0}
	count, err := db.Query("SELECT COUNT(*)  FROM  ca_data WHERE Name= ?", caName)
	checkErr(err)
	c := checkCount(count)
	if c == 1 {
		result = ReadCaItem(db, caName)
	}
	return result, c
}

/* check if CA is present */
func checkCount(rows *sql.Rows) (count int) {
	for rows.Next() {
		err := rows.Scan(&count)
		checkErr(err)
	}
	return count
}

/* store a row entry in CA table */
func StoreCaItem(db *sql.DB, item *CaTable) {
	sql_additem := `INSERT OR REPLACE INTO ca_data(
                        Name,
                        Csr,
						Cert,
                        Key,
                        Fingerprint,
                        FpAlgo,
                        Validity,
                        EnrollCount,
						Serial
                        ) values(?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `
	stmt, err := db.Prepare(sql_additem)
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	_, err2 := stmt.Exec(item.Name, item.Csr, item.Cert, item.Key,
		item.Fingerprint, item.FpAlgo, item.Validity,
		item.EnrollCount, item.Serial)
	if err2 != nil {
		panic(err2)
	}
}

/* read CA table */
func ReadCaTable(db *sql.DB) []CaTable {
	sql_readall :=
		`SELECT Name, Csr, Cert, Key, Fingerprint, FpAlgo, Validity, EnrollCount, Serial FROM ca_data`
	rows, err := db.Query(sql_readall)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	var result []CaTable
	for rows.Next() {
		item := CaTable{}
		err2 := rows.Scan(&item.Name, &item.Csr, &item.Cert, &item.Key,
			&item.Fingerprint, &item.FpAlgo, &item.Validity,
			&item.EnrollCount, &item.Serial)
		if err2 != nil {
			panic(err2)
		}
		result = append(result, item)
	}
	return result
}

/* read a CA table row based on CA name */
func ReadCaItem(db *sql.DB, caName string) CaTable {
	sql_readall :=
		`SELECT Name, Csr, Cert, Key, Fingerprint, FpAlgo, Validity, EnrollCount, Serial FROM ca_data WHERE Name = ?`
	rows, err := db.Query(sql_readall, caName)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	item := CaTable{}
	rows.Next()
	err2 := rows.Scan(&item.Name, &item.Csr, &item.Cert, &item.Key,
		&item.Fingerprint, &item.FpAlgo, &item.Validity,
		&item.EnrollCount, &item.Serial)
	checkErr(err2)
	fmt.Println(item.Name)
	return item

}

/* create Certificate table */
func CreateCertTable(db *sql.DB) {
	sql_table := `
        CREATE TABLE IF NOT EXISTS cert_data(
                EnrollId TEXT NOT NULL PRIMARY KEY,
                Certificate TEXT,
                Csr TEXT,
                Validity INT,
                Signature STRING,
                CaName STRING
        )`
	_, err := db.Exec(sql_table)
	checkErr(err)

}

/* store a row in Certificate table */
func StoreCertItem(db *sql.DB, item CertTable) {
	sql_additem := `INSERT OR REPLACE INTO cert_data(
                        EnrollId,
                        Certificate,
                        Csr,
                        Validity,
                        Signature,
                        CaName
                        ) values(?, ?, ?, ?, ?, ?)
                        `
	stmt, err := db.Prepare(sql_additem)
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	_, err2 := stmt.Exec(item.EnrollId, item.Certificate, item.Csr,
		item.Validity, item.Signature, item.CaName)
	if err2 != nil {
		panic(err2)
	}
}

/* read Certificate table */
func ReadCertTable(db *sql.DB) []CertTable {
	sql_readall :=
		`SELECT EnrollId, Certificate, Csr, Validity, Signature, CaName FROM cert_data`

	rows, err := db.Query(sql_readall)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	var result []CertTable
	for rows.Next() {
		item := CertTable{}
		err2 := rows.Scan(&item.EnrollId, &item.Certificate, &item.Csr,
			&item.Validity, &item.Signature, &item.CaName)
		if err2 != nil {
			panic(err2)
		}
		result = append(result, item)
	}
	return result
}

/* create Enrollment table if not created */
func CreateEnrollTable(db *sql.DB) {
	sql_table := `
        CREATE TABLE IF NOT EXISTS enroll_data(
                EnrollId TEXT NOT NULL PRIMARY KEY,
                Secret TEXT,
                Attributes TEXT,
                Status INT,
                Role STRING,
				Ca STRING,
                CaProfile STRING
        )`
	_, err := db.Exec(sql_table)
	checkErr(err)
}

/* store a row in Enrollment table */
func StoreEnrollItem(db *sql.DB, item EnrollTable) {
	sql_additem := `INSERT OR REPLACE INTO enroll_data(
                        EnrollId,
                        Secret,
                        Attributes,
                        Status,
                        Role,
						Ca,
                        CaProfile
                        ) values(?, ?, ?, ?, ?, ?, ?)
                        `
	stmt, err := db.Prepare(sql_additem)
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	_, err2 := stmt.Exec(item.EnrollId, item.Secret, item.Attributes, item.Status, item.Role, item.Ca, item.CaProfile)
	if err2 != nil {
		panic(err2)
	}
}

func SearchEnrollItem(db *sql.DB, enrollid string) (EnrollTable, int) {
	result := EnrollTable{"", "", "", 0, "", "", ""}
	count, err := db.Query("SELECT COUNT(*) FROM enroll_data  WHERE EnrollId= ?", enrollid)
	checkErr(err)
	c := checkCount(count)
	if c == 1 {
		result = ReadEnrollTableItem(db, enrollid)
	}
	return result, c
}

func ReadEnrollTableItem(db *sql.DB, enrollid string) EnrollTable {
	sql_readall :=
		`SELECT EnrollId, Secret, Attributes, Status, Role, Ca, CaProfile FROM enroll_data WHERE EnrollId = ?`
	rows, err := db.Query(sql_readall, enrollid)
	if err != nil {
		fmt.Printf("\nGot Error while reading Enroll Table [%s]", err)
	}
	defer rows.Close()
	item := EnrollTable{}
	rows.Next()
	err2 := rows.Scan(&item.EnrollId, &item.Secret, &item.Attributes,
		&item.Status, &item.Role, &item.Ca, &item.CaProfile)
	checkErr(err2)
	fmt.Println(item.EnrollId)
	return item
}

/* read Enrollment table */
func ReadEnrollTable(db *sql.DB) []EnrollTable {
	sql_readall :=
		`SELECT EnrollId, Secret, Attributes, Status, Role, Ca, CaProfile FROM enroll_data`

	rows, err := db.Query(sql_readall)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	var result []EnrollTable
	for rows.Next() {
		item := EnrollTable{}
		err2 := rows.Scan(&item.EnrollId, &item.Secret, &item.Attributes,
			&item.Status, &item.Role, &item.Ca, &item.CaProfile)
		if err2 != nil {
			panic(err2)
		}
		result = append(result, item)
	}
	return result
}

/* create CRL table if not created */
func CreateCrlTable(db *sql.DB) {
	// create table if not exists
	sql_table := `
        CREATE TABLE IF NOT EXISTS crl_data(
                Name TEXT NOT NULL PRIMARY KEY,
                Validity INT,
                Updt TEXT,
                Time INT
        )`
	_, err := db.Exec(sql_table)
	checkErr(err)
}

/* store Crl table row */
func StoreCrlItem(db *sql.DB, item CrlTable) {
	sql_additem := `INSERT OR REPLACE INTO crl_data(
                        Name,
                        Validity,
                        Updt,
                        Time
                        ) values(?, ?, ?, ?)
                        `
	stmt, err := db.Prepare(sql_additem)
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	_, err2 := stmt.Exec(item.Name, item.Validity, item.Updt, item.Time)
	if err2 != nil {
		panic(err2)
	}
}

/* read Crl table */
func ReadCrlTable(db *sql.DB) []CrlTable {
	sql_readall :=
		`SELECT NAme, Validity, Updt, Time FROM crl_data`

	rows, err := db.Query(sql_readall)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	var result []CrlTable
	for rows.Next() {
		item := CrlTable{}
		err2 := rows.Scan(&item.Name, &item.Validity, &item.Updt,
			&item.Time)
		if err2 != nil {
			panic(err2)
		}
		result = append(result, item)
	}
	return result
}

/* create CA Profile table if not created */
func CreateCaProfileTable(db *sql.DB) {
	sql_table := `
        CREATE TABLE IF NOT EXISTS caprofile_data(
                Name TEXT NOT NULL PRIMARY KEY,
                O TEXT,
                OU TEXT,
                CN TEXT,
                IP TEXT,
                Host INT,
                IsCa INT,
                Pathlength INT,
                Validity INT
        )`
	_, err := db.Exec(sql_table)
	checkErr(err)
}

/* store a row in CA Profile table */
func StoreCaProfileItem(db *sql.DB, item CaProfileTable) {
	sql_additem := `INSERT OR REPLACE INTO caprofile_data(
                        Name,
                        O,
                        OU,
                        CN,
                        IP,
                        Host,
                        IsCa,
                        Pathlength,
                        Validity
                        ) values(?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `
	stmt, err := db.Prepare(sql_additem)
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	_, err2 := stmt.Exec(item.Name, item.O, item.OU, item.CN, item.IP, item.Host, item.IsCa, item.Pathlength, item.Validity)
	if err2 != nil {
		panic(err2)
	}
}

/* read CA Profile table */
func ReadCaProfileTable(db *sql.DB) []CaProfileTable {
	sql_readall :=
		`SELECT Name, O, OU, CN, IP, Host, IsCa, Pathlength, Validity FROM caprofile_data`

	rows, err := db.Query(sql_readall)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	var result []CaProfileTable
	for rows.Next() {
		item := CaProfileTable{}
		err2 := rows.Scan(&item.Name, &item.O, &item.OU,
			&item.CN, &item.IP, &item.Host, &item.IsCa, &item.Pathlength, &item.Validity)
		if err2 != nil {
			panic(err2)
		}
		result = append(result, item)
	}
	return result
}
