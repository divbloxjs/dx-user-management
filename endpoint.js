const dxUserManagementController = require("./index");
const divbloxEndpointBase = require("divbloxjs/dx-core-modules/endpoint-base");

/**
 * Provides all the relevant endpoints for the Divblox User Management package
 */
class DxUserManagementEndpoint extends divbloxEndpointBase {
    /**
     * Standard DivbloxEndpointBase constructor
     * @param dxInstance
     */
    constructor(dxInstance = null) {
        super(dxInstance);

        this.endpointName = "dxUserManagement"; // Change this to set the actual url endpoint
        this.endpointDescription = "dxUserManagement endpoint"; // Change this to be more descriptive of the endpoint

        this.controller = new dxUserManagementController(dxInstance);

        const hiddenOperations =
            typeof this.controller.packageOptions["hiddenOperations"] !== "undefined"
                ? this.controller.packageOptions["hiddenOperations"]
                : [];

        const operationAccess =
            typeof this.controller.packageOptions["operationAccess"] !== "undefined"
                ? this.controller.packageOptions["operationAccess"]
                : {};

        const listUserAccounts = this.getOperationDefinition({
            operationName: "listUserAccounts",
            allowedAccess:
                typeof operationAccess["listUserAccounts"] !== "undefined"
                    ? operationAccess["listUserAccounts"]
                    : ["super user"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Lists the current user accounts in the database",
            operationDescription: "Lists the current user accounts in the database",
            parameters: [
                this.getInputParameter({ name: "offset", type: "query" }),
                this.getInputParameter({ name: "limit", type: "query" }),
                this.getInputParameter({ name: "loginName", type: "query" }),
                this.getInputParameter({ name: "emailAddress", type: "query" }),
            ], // An array of this.getInputParameter()
            requestType: "GET", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: {}, // this.getSchema()
            responseSchema: this.getArraySchema(this.dxInstance.getEntitySchema("userAccount"), "userAccounts"),
            disableSwaggerDoc: hiddenOperations.indexOf("listUserAccounts") !== -1,
        });

        const updateUserAccount = this.getOperationDefinition({
            operationName: "userAccount",
            allowedAccess:
                typeof operationAccess["updateUserAccount"] !== "undefined"
                    ? operationAccess["updateUserAccount"]
                    : ["super user"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Modifies a user account",
            operationDescription:
                "Modifies a user account with the details provided.<br>" +
                "If a password is supplied, this will be properly hashed and salted for later comparison.",
            parameters: [this.getInputParameter({ name: "id", type: "query" })], // An array of this.getInputParameter()
            requestType: "PUT", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: this.dxInstance.getEntitySchema("userAccount", true), // this.getSchema()
            responseSchema: this.getSchema({ message: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("updateUserAccount") !== -1,
        });

        const updateCurrentUserAccount = this.getOperationDefinition({
            operationName: "updateCurrentUserAccount",
            allowedAccess: ["anonymous"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Modifies the current user account",
            operationDescription:
                "Modifies the current user account with the details provided.<br>" +
                "If a password is supplied, this will be properly hashed and salted for later comparison.",
            parameters: [], // An array of this.getInputParameter()
            requestType: "PUT", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: this.dxInstance.getEntitySchema("userAccount", true), // this.getSchema()
            responseSchema: this.getSchema({ message: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("updateCurrentUserAccount") !== -1,
        });

        const uploadProfilePicture = this.getOperationDefinition({
            operationName: "uploadProfilePicture",
            allowedAccess: ["anonymous"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Saves the uploaded picture as the current user's profile picture",
            operationDescription: "Saves the uploaded picture as the current user's profile picture",
            parameters: [], // An array of this.getInputParameter()
            requestType: "POST", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: {},
            responseSchema: this.getSchema({ fileUrl: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("updateCurrentUserAccount") !== -1,
        });

        const createUserAccount = this.getOperationDefinition({
            operationName: "userAccount",
            allowedAccess:
                typeof operationAccess["createUserAccount"] !== "undefined"
                    ? operationAccess["createUserAccount"]
                    : ["super user"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Creates a new user account",
            operationDescription:
                "Creates a new user account with the details provided.<br>" +
                "If a password is supplied, this will be properly hashed and salted for later comparison.<br>" +
                "All fields are optional, except for 'loginName' which is required because it is a unique username " +
                "that the account is identified by.",
            parameters: [], // An array of this.getInputParameter()
            requestType: "POST", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: this.dxInstance.getEntitySchema("userAccount", true), // this.getSchema()
            responseSchema: this.getSchema({ id: "integer" }),
            disableSwaggerDoc: hiddenOperations.indexOf("createUserAccount") !== -1,
        });

        const deleteUserAccount = this.getOperationDefinition({
            operationName: "userAccount",
            allowedAccess:
                typeof operationAccess["deleteUserAccount"] !== "undefined"
                    ? operationAccess["deleteUserAccount"]
                    : ["super user"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Deletes a user account",
            operationDescription: "Deletes a user account matching the provided id",
            parameters: [this.getInputParameter({ name: "id", type: "query" })], // An array of this.getInputParameter()
            requestType: "DELETE", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: {}, // this.getSchema()
            responseSchema: this.getSchema({ message: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("deleteUserAccount") !== -1,
        });

        const registerUserAccount = this.getOperationDefinition({
            operationName: "registerUser",
            allowedAccess: ["anonymous"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Registers a new user account",
            operationDescription:
                "Creates a new user account with the details provided.<br>" +
                "Password is required and will be properly hashed and salted for later comparison.<br>" +
                "All fields are optional, but either 'loginName' or 'emailAdress' needs to be provided." +
                " If 'loginName' is provided it needs to be unique since it will be the " +
                "username that the account is identified by.<br>If 'emailAddress' is provided, it will be validated " +
                "and also used as the value for 'loginName' if 'loginName' is NOT provided.",
            parameters: [], // An array of this.getInputParameter()
            requestType: "POST", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: this.getSchema({
                firstName: "string",
                lastName: "string",
                emailAddress: "string",
                loginName: "string",
                password: "string",
            }),
            responseSchema: this.getSchema({ message: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("registerUserAccount") !== -1,
        });

        const authenticateUserAccount = this.getOperationDefinition({
            operationName: "authenticate",
            allowedAccess: ["anonymous"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Authenticates a user account",
            operationDescription: "Authenticates a user account by its loginName and password",
            parameters: [], // An array of this.getInputParameter()
            requestType: "POST", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: this.getSchema({ loginName: "string", password: "string" }),
            responseSchema: this.getSchema({ jwt: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("authenticateUserAccount") !== -1,
        });

        const logoutUserAccount = this.getOperationDefinition({
            operationName: "logout",
            allowedAccess: ["anonymous"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Logs out a user account",
            operationDescription: "Logs out a user account by removing the jwt http-only cookie from the browser",
            parameters: [], // An array of this.getInputParameter()
            requestType: "GET", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: {},
            responseSchema: this.getSchema({ message: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("logoutUserAccount") !== -1,
        });

        const sendPasswordResetToken = this.getOperationDefinition({
            operationName: "sendPasswordResetToken",
            allowedAccess: ["anonymous"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Generates and sends a new password reset token",
            operationDescription:
                "Generates a new password reset token by using the email address provided to " +
                "associate it with the correct user account",
            parameters: [this.getInputParameter({ name: "emailAddress", type: "query" })], // An array of this.getInputParameter()
            requestType: "GET", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: {},
            responseSchema: this.getSchema({ token: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("sendPasswordResetToken") !== -1,
        });

        const resetPasswordFromToken = this.getOperationDefinition({
            operationName: "resetPasswordFromToken",
            allowedAccess: ["anonymous"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Resets a password using password reset token",
            operationDescription: "Resets a password using password reset token",
            parameters: [this.getInputParameter({ name: "token", type: "query" })], // An array of this.getInputParameter()
            requestType: "POST", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: this.getSchema({ password: "string" }),
            responseSchema: this.getSchema({ message: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("resetPasswordFromToken") !== -1,
        });

        const sendAccountVerificationToken = this.getOperationDefinition({
            operationName: "sendAccountVerificationToken",
            allowedAccess: ["anonymous"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Generates and sends a new account verification token",
            operationDescription:
                "Generates a new account verification token by using the email address provided to " +
                "associate it with the correct user account",
            parameters: [this.getInputParameter({ name: "emailAddress", type: "query" })], // An array of this.getInputParameter()
            requestType: "GET", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: {},
            responseSchema: this.getSchema({ token: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("sendAccountVerificationToken") !== -1,
        });

        const verifyAccountFromToken = this.getOperationDefinition({
            operationName: "verifyAccountFromToken",
            allowedAccess: ["anonymous"], // If this array does not contain "anonymous", a JWT token will be expected in the Auth header
            operationSummary: "Verifies an userAccount using the provided token",
            operationDescription: "Verifies an userAccount using the provided token",
            parameters: [this.getInputParameter({ name: "token", type: "query" })], // An array of this.getInputParameter()
            requestType: "GET", // GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE
            requestSchema: {},
            responseSchema: this.getSchema({ message: "string" }),
            disableSwaggerDoc: hiddenOperations.indexOf("verifyAccountFromToken") !== -1,
        });

        this.declareOperations([
            listUserAccounts,
            createUserAccount,
            updateUserAccount,
            updateCurrentUserAccount,
            uploadProfilePicture,
            deleteUserAccount,
            authenticateUserAccount,
            logoutUserAccount,
            registerUserAccount,
            sendPasswordResetToken,
            resetPasswordFromToken,
            sendAccountVerificationToken,
            verifyAccountFromToken,
        ]);
    }

    /**
     * Specialization of the base executeOperation function (See parent class) to allow for all our specified operations
     * to execute
     * @param operation
     * @param request
     * @return {Promise<boolean>}
     */
    async executeOperation(operation, request) {
        if (!(await super.executeOperation(operation, request))) {
            return false;
        }

        // Here we have to deal with our custom operations
        switch (operation) {
            case "listUserAccounts":
                const offset = typeof request.query["offset"] !== "undefined" ? request.query["offset"] : 0;
                const limit = typeof request.query["limit"] !== "undefined" ? request.query["limit"] : 50;

                const constraints = {};
                if (typeof request.query["loginName"] !== "undefined") {
                    constraints["loginName"] = request.query["loginName"];
                }
                if (typeof request.query["emailAddress"] !== "undefined") {
                    constraints["emailAddress"] = request.query["emailAddress"];
                }

                await this.listUserAccounts(offset, limit, constraints);
                break;
            case "userAccount":
                switch (request.method.toLowerCase()) {
                    case "post":
                        await this.createUserAccount(request.body);
                        break;
                    case "put":
                        const userAccountId = typeof request.query["id"] !== "undefined" ? request.query["id"] : -1;
                        await this.updateUserAccount(userAccountId, request.body);
                        break;
                    case "delete":
                        await this.deleteUserAccount(request.query["id"]);
                        break;
                }
                break;
            case "updateCurrentUserAccount":
                await this.updateCurrentUserAccount(request.body, this.currentGlobalIdentifier);
                break;
            case "uploadProfilePicture":
                await this.uploadProfilePicture(request, this.currentGlobalIdentifier);
                break;
            case "authenticate":
                await this.authenticateUserAccount(request.body);
                break;
            case "logout":
                this.logoutUserAccount();
                break;
            case "registerUser":
                await this.registerUserAccount(request.body);
                break;
            case "sendPasswordResetToken":
                await this.sendPasswordResetToken(request.query["emailAddress"]);
                break;
            case "resetPasswordFromToken":
                await this.resetPasswordFromToken(request.query["token"], request.body);
                break;
            case "sendAccountVerificationToken":
                await this.sendAccountVerificationToken(request.query["emailAddress"]);
                break;
            case "verifyAccountFromToken":
                await this.verifyAccountFromToken(request.query["token"], this.currentGlobalIdentifier);
                break;
        }

        return true;
    }

    //#region Operation implementations that reference their controller counterparts. See controller file for details docs

    async listUserAccounts(offset = 0, limit = 50, constraints = {}) {
        const userAccounts = await this.controller.listUserAccounts(offset, limit, constraints);
        this.addResultDetail({ userAccounts: userAccounts });
        this.setResult(true);
    }

    async createUserAccount(userAccountDetail) {
        const createId = await this.controller.createUserAccount(userAccountDetail);
        this.addResultDetail({ id: createId });
        if (createId === -1) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        } else {
            this.setResult(true);
        }
    }

    async updateUserAccount(userAccountId = -1, userAccountDetail) {
        if (userAccountId === -1) {
            this.setResult(false, "Invalid userAccount Id provided");
            return;
        }

        if (!(await this.controller.updateUserAccount(userAccountId, userAccountDetail))) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        } else {
            this.setResult(true, "Details updated!");
        }
    }

    async updateCurrentUserAccount(userAccountDetail, uniqueIdentifier) {
        if (!(await this.controller.setCurrentUserAccountFromGlobalIdentifier(uniqueIdentifier))) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
            return;
        }

        if (!(await this.controller.updateCurrentUserAccount(userAccountDetail))) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        } else {
            this.setResult(true, "Details updated!");
        }
    }

    async uploadProfilePicture(request, uniqueIdentifier) {
        if (!request.files || Object.keys(request.files).length === 0) {
            this.setResult(false, "No files were uploaded");
            return;
        }

        if (!(await this.controller.setCurrentUserAccountFromGlobalIdentifier(uniqueIdentifier))) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
            return;
        }

        const fileStaticUrl = await this.controller.uploadProfilePicture(Object.values(request.files)[0]);
        if (fileStaticUrl === null) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
            return;
        }

        this.addResultDetail({ fileUrl: fileStaticUrl });
        this.setResult(true, "File uploaded");
    }

    async deleteUserAccount(userAccountId) {
        if (!(await this.controller.deleteUserAccount(userAccountId))) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        } else {
            this.setResult(true, "Successfully deleted");
        }
    }

    async authenticateUserAccount(loginDetails) {
        const jwt = await this.controller.authenticateUser(loginDetails["loginName"], loginDetails["password"]);
        this.addResultDetail({ jwt: jwt });
        if (jwt === null) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        } else {
            this.setCookie("jwt", jwt);
            this.setResult(true);
        }
    }

    logoutUserAccount() {
        this.setCookie("jwt", null, true, true, -1);
        this.setResult(true, "User logged out");
    }

    async registerUserAccount(userAccountDetail) {
        const createId = await this.controller.registerUserAccount(userAccountDetail);
        if (createId === -1) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        } else {
            this.setResult(true, " User Account created!");
        }
    }

    async sendPasswordResetToken(emailAddress) {
        if (!(await this.controller.sendPasswordResetToken(emailAddress))) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        } else {
            this.setResult(true, "Token sent to user(s)");
        }
    }

    async resetPasswordFromToken(token, requestBody) {
        if (typeof requestBody["password"] === "undefined") {
            this.setResult(false, "No password was provided");
            return;
        }

        if (!(await this.controller.resetPasswordFromToken(token, requestBody["password"]))) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        } else {
            this.setResult(true, "Password reset successfully");
        }
    }

    async sendAccountVerificationToken(emailAddress) {
        if (!(await this.controller.sendAccountVerificationToken(emailAddress))) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        } else {
            this.setResult(true, "Token sent to user(s)");
        }
    }

    async verifyAccountFromToken(token, uniqueIdentifier) {
        if (!(await this.controller.setCurrentUserAccountFromGlobalIdentifier(uniqueIdentifier))) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        }

        if (!(await this.controller.verifyAccountFromToken(token))) {
            const error = this.controller.getError().length > 0 ? this.controller.getError()[0] : "Unknown error";
            this.setResult(false, error);
        } else {
            this.setResult(true, "Account verified successfully");
        }
    }

    //#endregion
}

module.exports = DxUserManagementEndpoint;
