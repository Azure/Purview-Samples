USE master
go
DECLARE @V_USER_NAME NVARCHAR(80)
DECLARE @V_STATEMENT_1 NVARCHAR(100)
DECLARE @V_PARAMETERS NVARCHAR(100)
DECLARE @V_STATEMENT_2 NVARCHAR(300)
DECLARE @V_PASSWORD NVARCHAR(50)
DECLARE @V_CREATE_USER NVARCHAR(150)
DECLARE @V_ADD_USER NVARCHAR(100)
DECLARE @V_ERRORMESSAGE NVARCHAR(4000)  
DECLARE @I_ERRORSEVERITY INT
DECLARE @I_ERRORSTATE INT  
/*================================================
Set these variables before executing the script
==================================================*/
SET @V_USER_NAME = N'purview_scanner'
SET @V_PASSWORD = N'HappyDays123'
SET @V_STATEMENT_1 = 'CREATE LOGIN '+QUOTENAME(@V_USER_NAME)+' WITH PASSWORD=N'+''''+@V_PASSWORD+''''
SET @V_PARAMETERS = N' ,DEFAULT_DATABASE=[master],CHECK_EXPIRATION=OFF,CHECK_POLICY=OFF'
SET @V_STATEMENT_2 = @V_STATEMENT_1+@V_PARAMETERS
SET @V_CREATE_USER = 'USE ?'+' DROP USER IF EXISTS '+QUOTENAME(@V_USER_NAME)+';' +'CREATE USER '+QUOTENAME(@V_USER_NAME)+' FOR LOGIN '+QUOTENAME(@V_USER_NAME)+';'
SET @V_ADD_USER ='USE ?'+' ALTER ROLE [db_datareader] ADD MEMBER '+QUOTENAME(@V_USER_NAME)
/*================================================
Set the above variables before executing the script
==================================================*/
print(@V_STATEMENT_2)

 

IF NOT EXISTS (SELECT LOGINNAME FROM MASTER.DBO.SYSLOGINS 
               WHERE NAME = @V_USER_NAME)
BEGIN
    BEGIN TRY 
            EXECUTE sp_executesql @V_STATEMENT_2
            PRINT('The LOGIN '+@V_USER_NAME+ ' HAS BEEN CREATED SUCCESSFULLY!')
    END TRY
    BEGIN CATCH
            SELECT   
                @V_ERRORMESSAGE = ERROR_MESSAGE()+'.The Login could not be created.',  
                @I_ERRORSEVERITY = ERROR_SEVERITY(),  
                @I_ERRORSTATE = ERROR_STATE();  
  

 

                RAISERROR (@V_ERRORMESSAGE, -- Message text.  
                           @I_ERRORSEVERITY, -- Severity.  
                           @I_ERRORSTATE -- State.  
                           );  
       END CATCH   
END
/*---------------------------------------------------------------
== ADD the users
---------------------------------------------------------------*/
PRINT(@V_CREATE_USER)
BEGIN TRY 
            EXEC sp_MSforeachdb @V_CREATE_USER
            PRINT('The USER '+@V_USER_NAME+ ' HAS BEEN CREATED SUCCESSFULLY ON ALL DATABASES!')
END TRY
BEGIN CATCH
        SELECT   
            @V_ERRORMESSAGE = ERROR_MESSAGE()+'.The user could not be created.',  
            @I_ERRORSEVERITY = ERROR_SEVERITY(),  
            @I_ERRORSTATE = ERROR_STATE();  
  

 

        RAISERROR (@V_ERRORMESSAGE, -- Message text.  
                   @I_ERRORSEVERITY, -- Severity.  
                   @I_ERRORSTATE -- State.  
                   );  
END CATCH
PRINT(@V_ADD_USER)
BEGIN TRY 
            EXEC sp_MSforeachdb @V_ADD_USER
            PRINT('The USER '+@V_USER_NAME+ ' HAS BEEN ADDED SUCCESSFULLY TO ALL DATABASES!')
END TRY
BEGIN CATCH
        SELECT   
            @V_ERRORMESSAGE = ERROR_MESSAGE()+'.The user could not be created.',  
            @I_ERRORSEVERITY = ERROR_SEVERITY(),  
            @I_ERRORSTATE = ERROR_STATE();  
  

 

        RAISERROR (@V_ERRORMESSAGE, -- Message text.  
                   @I_ERRORSEVERITY, -- Severity.  
                   @I_ERRORSTATE -- State.  
                   );  
END CATCH