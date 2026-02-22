// src/dashboard-service.js
class DashboardService {
    constructor(accountManager, mafileManager) {
        this.accountManager = accountManager;
        this.mafileManager = mafileManager;
    }

    async getDashboardData() {
        const accounts = await this.accountManager.getAllAccounts();
        const mafiles = await this.mafileManager.getAllMAFiles();

        let totalPlaytime = 0;
        let totalGamesIdling = 0;
        let activeAccounts = 0;

        for (const account of accounts) {
            if (account.isOnline) {
                activeAccounts++;
            }
            totalPlaytime += account.playtime || 0;
            totalGamesIdling += account.gamesCount || 0;
        }

        return {
            totalAccounts: accounts.length,
            activeAccounts,
            totalGamesIdling,
            totalPlaytimeHours: totalPlaytime,
            totalMAFiles: mafiles.length,
            linkedMAFiles: mafiles.filter(m => m.linkedAccountId).length,
            recentAccounts: accounts.slice(0, 5),
            recentMAFiles: mafiles.slice(0, 5)
        };
    }

    async getAccountStats(accountId) {
        const account = await this.accountManager.getAccount(accountId);
        if (!account) return null;

        return {
            ...account,
            playtimeHistory: account.playtimeHistory || [],
            loginHistory: account.loginHistory || []
        };
    }

    async getSystemStats() {
        const accounts = await this.accountManager.getAllAccounts();
        
        return {
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            cpu: process.cpuUsage(),
            accounts: accounts.length,
            nodeVersion: process.version,
            platform: process.platform
        };
    }
}

module.exports = DashboardService;