const divbloxPackageControllerBase = require('divbloxjs/dx-core-modules/package-controller-base');
const userAccountController = require('divbloxjs/dx-orm/generated/user-account');
const oneTimeTokenController = require('divbloxjs/dx-orm/generated/one-time-token');
const fs = require("fs");
const dxUtils = require('dx-utils');
const bcrypt = require('bcrypt');
const saltRounds = 10;

/**
 * The Divblox User Management controller is responsible for all of the logic pertaining to user management within a
 * divbloxjs app. This includes all of the database interactions such as CRUD, registration, authentication and password
 * resets.
 */
class DxUserManagement extends divbloxPackageControllerBase {

    /**
     * The constructor is responsible for:
     * 1. Identifying and setting up the operations that should be hidden. This is useful when using this package in a
     *      production environment where you would not necessarily want to show the world the available user management
     *      operations.
     * 2. Setting up some package-specific variables used during password reset, such as email addresses and urls.
     * 3. Setting up templates that are used when sending emails.
     * @param dxInstance An instance of divbloxjs
     * @param packageName Should always just default to dx-user-management
     */
    constructor(dxInstance = null, packageName = 'dx-user-management') {
        super(dxInstance, packageName);

        if (typeof this.packageOptions["hiddenOperations"] === "undefined") {
            this.packageOptions["hiddenOperations"] = [];
        }

        if (typeof this.packageOptions["noReplyEmailAddress"] === "undefined") {
            this.packageOptions["noReplyEmailAddress"] = "to be defined";
        }

        if (typeof this.packageOptions["frontEndUrlBase"] === "undefined") {
            this.packageOptions["frontEndUrlBase"] = "#";
        }

        if (typeof this.packageOptions["frontEndResetPasswordPath"] === "undefined") {
            this.packageOptions["frontEndResetPasswordPath"] = "/reset-password";
        }

        this.resetPasswordPath = this.packageOptions["frontEndUrlBase"] +
            this.packageOptions["frontEndResetPasswordPath"];

        this.forgottenPasswordMessageTemplate = "" +
            "Dear [firstName],<br><br>" +
            "Use <a href=\"[resetPasswordLink]\">this link</a> to reset your password";

        if (typeof this.packageOptions["forgottenPasswordMessageTemplatePath"] !== "undefined") {
            this.forgottenPasswordMessageTemplate =
                fs.readFileSync(this.packageOptions["forgottenPasswordMessageTemplatePath"], 'utf-8');
        }
    }

    /**
     * Returns a list of userAccount objects
     * @param {number} offset The offset to use when querying the database
     * @param {number} limit The limit to use when querying the database
     * @param {*} constraints A list of constraints in {key:value} form that will be added the query
     * @return {Promise<*[]>} An array of userAccount objects
     */
    async listUserAccounts(offset = 0, limit = 50, constraints = {}) {
        let constraintStr = "";
        if (Object.keys(constraints).length > 0) {
            constraintStr = " WHERE";
            for (const constraint of Object.keys(constraints)) {
                constraintStr += " `"+this.dxInstance.dataLayer.getSqlReadyName(constraint)+"` = '"+constraints[constraint]+"' AND ";
            }

            constraintStr = constraintStr.substring(0,constraintStr.length - 4);
        }

        const queryStr = "SELECT * FROM `"+this.dxInstance.dataLayer.getSqlReadyName("userAccount")+"` "+constraintStr+
            "LIMIT "+limit+" OFFSET "+offset;

        const queryResult = await this.dxInstance.dataLayer.executeQuery(queryStr,
            this.dxInstance.dataLayer.getModuleNameFromEntityName("userAccount"));

        let returnArray = [];
        for (const item of queryResult) {
            returnArray.push(this.dxInstance.dataLayer.transformSqlObjectToJs(item));
        }

        return returnArray;
    }

    /**
     * Creates a new userAccount in the database using the provided data
     * @param {*} userAccountDetails Should match the userAccount schema
     * @return {Promise<number|*>} The id of the newly created account, or -1 if something went wrong. In the event of
     * an error, the error array is populated with a relevant message
     */
    async createUserAccount(userAccountDetails) {
        const userAccount = new userAccountController(this.dxInstance);
        userAccount.data = userAccountDetails;

        if ((typeof userAccount.data["emailAddress"] !== "undefined") &&
            userAccount.data["emailAddress"] !== null) {
            if (!dxUtils.validateEmailAddress(userAccount.data["emailAddress"])) {
                this.populateError("Invalid email address provided",true,true);
                return -1;
            }
        }

        if (userAccount.data["loginName"] !== '') {
            const existingUserAccount = await this.dxInstance.dataLayer.readByField('userAccount','loginName',userAccount.data["loginName"]);
            if (existingUserAccount !== null) {
                this.populateError("User already exists",true,true);
                return -1;
            }
        }

        if ((typeof userAccount.data["password"] !== "undefined") &&
            userAccount.data["password"] !== null) {
            userAccount.data["password"] = await bcrypt.hash(userAccount.data["password"], await bcrypt.genSalt(saltRounds));
            //We will compare this later with: const match = await bcrypt.compare(password, hashedPassword);
        }

        if (!await userAccount.save()) {
            this.populateError(userAccount.getError(),true,true);
        }

        if (typeof userAccount.data["id"] === "undefined") {
            userAccount.data["id"] = -1;
        }

        if (userAccount.data["id"] > 0) {
            const defaultGlobalIdentifierGrouping = await this.dxInstance.dataLayer.readByField(
                "globalIdentifierGrouping","name",this.dxInstance.getDefaultGlobalIdentifierGrouping());

            if (defaultGlobalIdentifierGrouping === null) {
                this.populateError("Identifier grouping configuration problem",true,true);
            } else {
                await this.dxInstance.createGlobalIdentifier(
                    'userAccount',
                    userAccount.data["id"],
                    [defaultGlobalIdentifierGrouping.id],
                    false);
            }
        }

        return userAccount.data["id"];
    }

    /**
     * Updates an userAccount with the data provided
     * @param {number} userAccountId The id of the userAccount that must be updated
     * @param {*} userAccountDetails Should match the userAccount schema
     * @return {Promise<boolean>} True if the update was successful, false otherwise with an error populated in the error array
     */
    async updateUserAccount(userAccountId = -1, userAccountDetails) {
        const userAccount = new userAccountController(this.dxInstance);
        if (!await userAccount.load(userAccountId)) {
            this.populateError(userAccount.getError(),true,true);
            return false;
        }

        for (const key of Object.keys(userAccountDetails)) {
            userAccount.data[key] = userAccountDetails[key];
        }
        if ((typeof userAccountDetails["emailAddress"] !== "undefined") &&
            userAccountDetails["emailAddress"] !== null) {
            if (!dxUtils.validateEmailAddress(userAccountDetails["emailAddress"])) {
                this.populateError("Invalid email address provided",true,true);
                return false;
            }
        }

        if (userAccountDetails["loginName"] !== '') {
            const existingUserAccount = await this.dxInstance.dataLayer.readByField('userAccount',
                'loginName', userAccountDetails["loginName"]);
            if ((existingUserAccount !== null) && (existingUserAccount.id !== userAccountId)) {
                this.populateError("User already exists",true,true);
                return false;
            }
        }

        if ((typeof userAccountDetails["password"] !== "undefined") &&
            userAccountDetails["password"] !== null) {
            userAccount.data["password"] = await bcrypt.hash(userAccountDetails["password"], await bcrypt.genSalt(saltRounds));
        }

        if (!await userAccount.save()) {
            this.populateError(userAccount.getError(),true,true);
            return false;
        }

        return true;
    }

    /**
     * Deletes the relevant userAccount from the database
     * @param {number} userAccountId The id of the userAccount to remove
     * @return {Promise<boolean>} True if successfully deleted, false otherwise with an error populated in the error array
     */
    async deleteUserAccount(userAccountId) {
        const userAccount = new userAccountController(this.dxInstance);

        if (!await userAccount.load(userAccountId)) {
            this.populateError("Could not locate user account",true,true);
            return false;
        }

        if (!await userAccount.delete()) {
            this.populateError(userAccount.getError(),true,true);
            return false;
        }

        return true;
    }

    /**
     * Authenticates a user using the data provided
     * @param {string} loginName The loginName (userName) of the userAccount to authenticate for
     * @param {string} password The password to check
     * @return {Promise<null|*>} Null or A JSON Web Token (JWT) that can be used as authentication credentials for the
     * user. If null is returned it means the authentication was not successful and an error will be populated in the
     * error array
     */
    async authenticateUser(loginName, password) {
        let jwtReturned = null;

        if (typeof loginName === "undefined") {
            this.populateError("No login name provided",true,true);
            return jwtReturned;
        }

        const existingUserAccount = new userAccountController(this.dxInstance);
        if (!await existingUserAccount.loadByField('loginName', loginName)) {
            this.populateError("Invalid credentials",true,true);
            return jwtReturned;
        }

        const passwordMatches = await bcrypt.compare(password, existingUserAccount.data.password);
        if (!passwordMatches) {
            this.populateError("Invalid credentials",true,true);
            return jwtReturned;
        }

        const globalIdentifier = await this.dxInstance.getGlobalIdentifierByLinkedEntity("userAccount", existingUserAccount.data.id);
        if (globalIdentifier === null) {
            this.populateError("Invalid credentials",true,true);
            return jwtReturned;
        }

        jwtReturned = await this.dxInstance.jwtWrapper.issueJwt(globalIdentifier.uniqueIdentifier);
        return jwtReturned;
    }

    /**
     * Similar to the createAccount function, but intended for anonymous users who are creating their own accounts
     * @param {*} userAccountDetails Should match the userAccount schema
     * @return {Promise<*|number>} The id of the newly created account, or -1 if something went wrong. In the event of
     * an error, the error array is populated with a relevant message
     */
    async registerUserAccount(userAccountDetails) {
        const userAccount = new userAccountController(this.dxInstance);
        userAccount.data = userAccountDetails;

        if ((typeof userAccount.data["emailAddress"] !== "undefined") &&
            (userAccount.data["emailAddress"] !== null) && (userAccount.data["emailAddress"] !== '')) {
            if (!dxUtils.validateEmailAddress(userAccount.data["emailAddress"])) {
                this.populateError("Invalid email address provided",true,true);
                return -1;
            }
        } else {
            if (userAccount.data["loginName"] === '') {
                this.populateError("Either 'loginName' or 'emailAddress' must be provided",true,true);
                return -1;
            }
        }

        if (userAccount.data["loginName"] === '') {
            userAccount.data["loginName"] = userAccount.data["emailAddress"];
        }

        const existingUserAccount = new userAccountController(this.dxInstance);
        if (await existingUserAccount.loadByField('loginName', userAccount.data["loginName"])) {
            this.populateError("User already exists",true,true);
            return -1;
        }

        if ((typeof userAccount.data["password"] !== "undefined") &&
            userAccount.data["password"] !== null) {
            userAccount.data["password"] = await bcrypt.hash(userAccount.data["password"], await bcrypt.genSalt(saltRounds));
        } else {
            // We will not enforce any password policy here. This can be done in a specialization
            this.populateError("Password is required.",true,true);
            return -1;
        }

        if (!await userAccount.save()) {
            this.populateError(userAccount.getError(),true,true);
        }

        if (typeof userAccount.data["id"] === "undefined") {
            userAccount.data["id"] = -1;
        }

        if (userAccount.data["id"] > 0) {
            const defaultGlobalIdentifierGrouping = await this.dxInstance.dataLayer.readByField(
                "globalIdentifierGrouping","name",this.dxInstance.getDefaultGlobalIdentifierGrouping());

            if (defaultGlobalIdentifierGrouping === null) {
                this.populateError("Identifier grouping configuration problem",true,true);
            } else {
                await this.dxInstance.createGlobalIdentifier(
                    'userAccount',
                    userAccount.data["id"],
                    [defaultGlobalIdentifierGrouping.id],
                    false);
            }
        }

        return userAccount.data["id"];
    }

    /**
     * Generates a new token that will be used to reset a given user or users' password. This token is automatically
     * sent via email to the relevant recipient(s). Note, your project should implement the "sendEmail" function provided
     * in divbloxjs in order for this function to work correctly.
     * @param {string} emailAddress The email address of the user(s) to generate a token for
     * @return {Promise<boolean>} Returns true if the token was successfully sent, false otherwise with an error
     * populated in the error array. Note, the token could've been successfully generated even if this function returns
     * false.
     */
    async generatePasswordResetToken(emailAddress) {
        const dateNow = dxUtils.getLocalDateStringFromCurrentDate(new Date());

        const expiredTokensQuery = "SELECT "+this.dxInstance.dataLayer.getSqlReadyName("id")+" FROM "+
            this.dxInstance.dataLayer.getSqlReadyName('oneTimeToken')+" " +
            "WHERE "+this.dxInstance.dataLayer.getSqlReadyName('expiryTime')+" < '"+dateNow+"'";

        const expiredTokens = await this.dxInstance.dataLayer.executeQuery(
            expiredTokensQuery,
            this.dxInstance.dataLayer.getModuleNameFromEntityName('oneTimeToken'));

        if (Object.keys(expiredTokens).length > 0) {
            let expiredTokenIdStr = '';

            for (const token of expiredTokens) {
                if (expiredTokenIdStr !== '') {
                    expiredTokenIdStr += ','
                }

                expiredTokenIdStr += token.id;
            }

            const cleanUpTokensQuery = "DELETE FROM "+
                this.dxInstance.dataLayer.getSqlReadyName('oneTimeToken')+" " +
                "WHERE "+this.dxInstance.dataLayer.getSqlReadyName('id')+" IN ("+expiredTokenIdStr+")";

            await this.dxInstance.dataLayer.executeQuery(
                cleanUpTokensQuery,
                this.dxInstance.dataLayer.getModuleNameFromEntityName('oneTimeToken'));
        }

        const userAccountsQuery = "SELECT "+this.dxInstance.dataLayer.getSqlReadyName("id")+" FROM "+
            this.dxInstance.dataLayer.getSqlReadyName('userAccount')+" " +
            "WHERE "+this.dxInstance.dataLayer.getSqlReadyName('emailAddress')+" = '"+emailAddress+"'";

        const userAccounts = await this.dxInstance.dataLayer.executeQuery(
            userAccountsQuery,
            this.dxInstance.dataLayer.getModuleNameFromEntityName('userAccount'));

        if (Object.keys(userAccounts).length === 0) {
            this.populateError("No users were found", true, true);

            // We return true here for security reasons. We don't this operation to be exploited to discover accounts
            return true;
        }

        let userAccountIdStr = '';

        for (const userAccount of userAccounts) {
            if (userAccountIdStr !== '') {
                userAccountIdStr += ','
            }

            userAccountIdStr += userAccount.id;
        }

        const oneTimeToken = new oneTimeTokenController(this.dxInstance);

        oneTimeToken.data.token = dxUtils.generateRandomString(24);
        oneTimeToken.data.expiryTime = new Date();

        // Let's set the expiry to 5 minutes
        oneTimeToken.data.expiryTime.setSeconds(oneTimeToken.data.expiryTime.getSeconds() + (5 * 60));

        if (!await oneTimeToken.save()) {
            this.populateError(oneTimeToken.getError(), true, true);
            return false;
        }

        const updateUserAccountsQuery = "UPDATE "+
            this.dxInstance.dataLayer.getSqlReadyName('userAccount')+" SET "+
            this.dxInstance.dataLayer.getSqlReadyName('one_time_token_user_account')+" = "+oneTimeToken.data.id+
            " WHERE "+this.dxInstance.dataLayer.getSqlReadyName('id')+" IN ("+userAccountIdStr+")";

        const queryResult = await this.dxInstance.dataLayer.executeQuery(
            updateUserAccountsQuery,
            this.dxInstance.dataLayer.getModuleNameFromEntityName('userAccount'));

        if (queryResult === null) {
            this.populateError(this.dxInstance.dataLayer.getError(), true, true);
            return false;
        }

        let emailMessage = this.forgottenPasswordMessageTemplate.replace('[firstName]', 'user');

        emailMessage = emailMessage.replace('[resetPasswordLink]',
                this.resetPasswordPath + "?token="+oneTimeToken.data.token);

        if (!await this.dxInstance.sendEmail({
            "fromAddress": this.packageOptions["noReplyEmailAddress"],
            "toAddresses": [emailAddress],
            "messageHtml": emailMessage})) {
            this.populateError(this.dxInstance.getError(), true, true);
            return false;
        }

        return true;
    }

    /**
     * Resets the relevant userAccount passwords using the token and new password provided
     * @param {string} token The password reset token to check on
     * @param {string} newPassword The new password to use.
     * @return {Promise<boolean>} True if password(s) were successfully reset, false otherwise with an error populated in
     * the error array.
     */
    async resetPasswordFromToken(token, newPassword) {
        if (typeof token === "undefined") {
            this.populateError("Invalid token provided", true, true);
            return false;
        }

        if ((typeof newPassword === "undefined") || (newPassword.length < 3)) {
            this.populateError("Invalid password provided", true, true);
            return false;
        }

        const oneTimeToken = new oneTimeTokenController(this.dxInstance);

        if (!await oneTimeToken.loadByField("token", token)) {
            this.populateError("Invalid token provided", true, true);
            return false;
        }

        const currentTimeStamp = new Date().getTime() / 1000;
        const storedDateTime = new Date(oneTimeToken.data.expiryTime);
        const storedTimeStamp = storedDateTime.getTime() / 1000;

        if (currentTimeStamp >= storedTimeStamp) {
            await oneTimeToken.delete();

            this.populateError("Expired token provided", true, true);
            return false;
        }

        const userAccountsQuery = "SELECT "+this.dxInstance.dataLayer.getSqlReadyName("id")+" FROM "+
            this.dxInstance.dataLayer.getSqlReadyName('userAccount')+" " +
            "WHERE "+this.dxInstance.dataLayer.getSqlReadyName('one_time_token_user_account')+" = '"+oneTimeToken.data.id+"'";

        const userAccounts = await this.dxInstance.dataLayer.executeQuery(
            userAccountsQuery,
            this.dxInstance.dataLayer.getModuleNameFromEntityName('userAccount'));

        if ((userAccounts === null) || (Object.keys(userAccounts).length === 0)) {
            this.populateError("No users were found", true, true);

            return false;
        }

        let userAccountIdStr = '';

        for (const userAccount of userAccounts) {
            if (userAccountIdStr !== '') {
                userAccountIdStr += ','
            }

            userAccountIdStr += userAccount.id;
        }

        const newPasswordToStore  = await bcrypt.hash(newPassword, await bcrypt.genSalt(saltRounds));

        const updateUserAccountsQuery = "UPDATE "+
            this.dxInstance.dataLayer.getSqlReadyName('userAccount')+" SET "+
            this.dxInstance.dataLayer.getSqlReadyName('password')+" = '"+newPasswordToStore+
            "' WHERE "+this.dxInstance.dataLayer.getSqlReadyName('id')+" IN ("+userAccountIdStr+")";

        const queryResult = await this.dxInstance.dataLayer.executeQuery(
            updateUserAccountsQuery,
            this.dxInstance.dataLayer.getModuleNameFromEntityName('userAccount'));

        if (queryResult === null) {
            this.populateError(this.dxInstance.dataLayer.getError(), true, true);
            return false;
        }

        await oneTimeToken.delete();

        return true;
    }
}

module.exports = DxUserManagement;