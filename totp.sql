CREATE FUNCTION dbo.HMAC (
  @algo VARCHAR(20),
  @key  VARBINARY(MAX),
  @data VARBINARY(MAX)
)
/* This function only takes VARBINARY parameters instead of VARCHAR
to prevent problems with implicit conversion from NVARCHAR to VARCHAR 
which result in incorrect hashes for inputs including non-ASCII characters. 
Always cast @key and @data parameters to VARBINARY when using this function. 
Tested against HMAC vectors for MD5 and SHA1 from RFC 2202 */

/*
List of secure hash algorithms (parameter @algo) supported by MSSQL 
version. This is what is passed to the HASHBYTES system function.
Omit insecure hash algorithms such as MD2 through MD5
2005-2008R2: SHA1 
2012-2016: SHA1 | SHA2_256 | SHA2_512 
*/
RETURNS VARBINARY(64) AS
BEGIN
DECLARE @ipad BIGINT
DECLARE @opad BIGINT
DECLARE @i VARBINARY(64)
DECLARE @o VARBINARY(64)
DECLARE @pos INTEGER

--SQL 2005 only allows XOR operations on integer types, so use bigint and interate 8 times
SET @ipad = CAST(0x3636363636363636 AS BIGINT) --constants from HMAC definition
SET @opad = CAST(0x5C5C5C5C5C5C5C5C AS BIGINT)

IF LEN(@key) > 64 --if the key is grater than 512 bits we hash it first per HMAC definition
  SET @key = CAST(HASHBYTES(@algo, @key) AS BINARY(64))
ELSE
  SET @key = CAST(@key AS BINARY(64)) --otherwise pad it out to 512 bits with zeros

SET @pos = 1
SET @i = CAST('' AS VARBINARY(64)) --initialize as empty binary value

WHILE @pos <= 57
BEGIN
  SET @i = @i + CAST((SUBSTRING(@key, @pos, 8) ^ @ipad) AS VARBINARY(64))
  SET @pos = @pos + 8
END

SET @pos = 1
SET @o = CAST('' AS VARBINARY(64)) --initialize as empty binary value

WHILE @pos <= 57
BEGIN
  SET @o = @o + CAST((SUBSTRING(@key, @pos, 8) ^ @opad) AS VARBINARY(64))
  SET @pos = @pos + 8
END

RETURN HASHBYTES(@algo, @o + HASHBYTES(@algo, @i + @data))
END
GO

CREATE FUNCTION dbo.TOTP (
  @x      VARCHAR(MAX),
  @time   INT = 30,
  @moving INT = 0
)

RETURNS NVARCHAR(6) AS
BEGIN
/* RFC 4648 compliant BASE32 decoding function, takes varchar data to decode as only parameter*/
DECLARE @p INT,
        @c BIGINT,
        @s BIGINT,
        @q BIGINT,
        @y BIGINT,
        @o VARBINARY(MAX),
        @i VARBINARY(64);

SET @o = CAST('' AS VARBINARY(MAX));
SET @p = 0; --initialize padding character count
--we can strip off padding characters since BASE32 is unambiguous without them
SET @x = REPLACE(@x, '=', '');
SET @p = DATALENGTH(@x) % 8; --encode with 40-bit blocks

IF @p <> 0
  SET @x = @x + SUBSTRING('AAAAAAAA', 1, 8 - @p);
SET @x = UPPER(@x);
SET @x = REPLACE(@x, '1', 'I');
SET @x = REPLACE(@x, '0', 'O');
SET @c = 1;

WHILE @c < DATALENGTH(@x) + 1
BEGIN
  SET @s = 0;
  SET @y = 0;
  WHILE @s < 8 --accumulate 8 characters (40 bits) at a time in a bigint
  BEGIN
    SET @y = @y * 32;
    SET @y = @y + CASE
                 WHEN SUBSTRING(@x, @c, 1) BETWEEN 'A'
                   AND 'Z' THEN ASCII(SUBSTRING(@x, @c, 1)) - 65
                 WHEN SUBSTRING(@x, @c, 1) BETWEEN '2'
                   AND '7' THEN ASCII(SUBSTRING(@x, @c, 1)) - 24
                 ELSE 0
                 END;
    SET @s = @s + 1;
    SET @c = @c + 1;
  END;

  SET @o = @o + SUBSTRING(CAST(@y AS BINARY(8)), 4, 5);
END;

--remove padding section
SET @o = CASE
        WHEN @p = 2 THEN SUBSTRING(@o, 1, DATALENGTH(@o) - 4)
        WHEN @p = 4 THEN SUBSTRING(@o, 1, DATALENGTH(@o) - 3)
        WHEN @p = 5 THEN SUBSTRING(@o, 1, DATALENGTH(@o) - 2)
        WHEN @p = 7 THEN SUBSTRING(@o, 1, DATALENGTH(@o) - 1)
        ELSE @o
        END;

SET @c = CAST(DATEDIFF(s, '1970-01-01 00:00:00', GETUTCDATE()) / @time AS BIGINT) + @moving;

SET @o = dbo.Hmac('SHA1', @o, @c);
SET @c = CAST(SUBSTRING(CONVERT(VARBINARY(20), @o), LEN(@o), 1) AS INT) & 0xF;

RETURN RIGHT('000000' + CAST(((CAST(SUBSTRING(@o, @c + 1, 1) AS INT) & 0x7F) * POWER(2, 24))
+ ((CAST(SUBSTRING(@o, @c + 2, 1) AS INT) & 0xFF) * POWER(2, 16))
+ ((CAST(SUBSTRING(@o, @c + 3, 1) AS INT) & 0xFF) * POWER(2, 8))
+ (CAST(SUBSTRING(@o, @c + 4, 1) AS INT) & 0xFF) % 10000000 AS NVARCHAR(10)), 6)


END
GO
