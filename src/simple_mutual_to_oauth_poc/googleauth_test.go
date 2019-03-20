package main

import (
      "encoding/base32"
      "github.com/dgryski/dgoogauth"

      "testing"
)

const TEST_TIMESTAMP = 1553078765000
const TEST_SECRET = "searchlight-secret"
const TEST_EXPECTED_TIMESTAMP = 51769292
const TEST_EXPECTED_CODE = 537662
const TEST_TIMESTAMP_WINDOW = 30000
const TEST_ENCODED_SECRET = "ONSWC4TDNBWGSZ3IOQWXGZLDOJSXI==="


func TestWithKnownValue(test *testing.T) {
  encodedSecretForComputation :=  base32.StdEncoding.EncodeToString([]byte(TEST_SECRET))
  timestampForComputation := int64(TEST_TIMESTAMP/TEST_TIMESTAMP_WINDOW)

  if timestampForComputation != TEST_EXPECTED_TIMESTAMP {
    test.Errorf("Got incorrect timestamp: %d, expected: %d", timestampForComputation, TEST_EXPECTED_TIMESTAMP)
  }

  result := dgoogauth.ComputeCode(encodedSecretForComputation, timestampForComputation)

  if result != TEST_EXPECTED_CODE {
    test.Errorf("Codes didn't match, got %d, expected %d", result, TEST_EXPECTED_CODE)
  }
}

func TestEncodingAndDecodingOfBase32(test *testing.T) {
  encodedSecret := base32.StdEncoding.EncodeToString([]byte(TEST_SECRET))
  if encodedSecret != TEST_ENCODED_SECRET {
    test.Errorf("Didn't get correct encoded value: \n%s, expected: \n%s", encodedSecret, TEST_ENCODED_SECRET)
  }

  decodedSecret, _ := base32.StdEncoding.DecodeString(encodedSecret)
  test.Logf("Got the following result: %s", decodedSecret)
}
