using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using System.Collections.Generic;
using System.Data.Entity;
using System;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;

namespace Identity_PasswordHistory.Models
{
    // You can add profile data for the user by adding more properties to your ApplicationUser class, please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationUser : IdentityUser
    {
        public ApplicationUser()
            : base()
        {
            if (PreviousUserPasswords == null)
            {
                PreviousUserPasswords = new List<PreviousPassword>();
            }
        }
        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }

        public virtual IList<PreviousPassword> PreviousUserPasswords { get; set; }
    }

    public class PreviousPassword
    {
        public PreviousPassword()
        {
            CreateDate = DateTimeOffset.Now;
        }

        [Key, Column(Order = 0)]
        public string Password { get; set; }
        public DateTimeOffset CreateDate { get; set; }

        [Key, Column(Order = 1)]
        public string UserId { get; set; }

        public virtual ApplicationUser User { get; set; }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext()
            : base("DefaultConnection")
        {
        }
    }

    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options)
        {
            var manager = new ApplicationUserManager(new ApplicationUserStore(new ApplicationDbContext()));
            // Configure the application user manager
            manager.UserValidator = new UserValidator<ApplicationUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };
            manager.PasswordValidator = new MinimumLengthValidator(6);
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.PasswordResetTokens = new DataProtectorTokenProvider(dataProtectionProvider.Create("PasswordReset"));
                manager.UserConfirmationTokens = new DataProtectorTokenProvider(dataProtectionProvider.Create("ConfirmUser"));
            }
            return manager;
        }

        public override async Task<IdentityResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword)
        {
            if (! await IsPreviousPassword(userId, newPassword))
            {
                return await Task.FromResult(IdentityResult.Failed("Cannot reuse old password"));
            }

            var store = Store as ApplicationUserStore;
            await store.AddToPreviousPasswordsAsync(await FindByIdAsync(userId), PasswordHasher.HashPassword(newPassword));
            
            return await base.ChangePasswordAsync(userId, currentPassword, newPassword);
        }

        public override async Task<IdentityResult> ResetPasswordAsync(string userId, string token, string newPassword)
        {
            if (!await IsPreviousPassword(userId, newPassword))
            {
                return await Task.FromResult(IdentityResult.Failed("Cannot reuse old password"));
            }

            var store = Store as ApplicationUserStore;
            await store.AddToPreviousPasswordsAsync(await FindByIdAsync(userId), PasswordHasher.HashPassword(newPassword));

            return await base.ResetPasswordAsync(userId, token, newPassword);
        }

        private async Task<bool> IsPreviousPassword(string userId, string newPassword)
        {
            var user = await FindByIdAsync(userId);

            if (user.PreviousUserPasswords.OrderByDescending(x => x.CreateDate).
                Select(x => x.Password).Take(5).Where(x => PasswordHasher.VerifyHashedPassword(x, newPassword) == PasswordVerificationResult.Success).
                Count() > 0)
            {
                return true;
            }

            return false;
        }
    }

    public class ApplicationUserStore : UserStore<ApplicationUser>
    {
        public ApplicationUserStore(DbContext context)
            : base(context)
        {

        }
        public override async Task CreateAsync(ApplicationUser user)
        {
            await base.CreateAsync(user);

            await AddToPreviousPasswordsAsync(user, user.PasswordHash);
        }

        public async Task AddToPreviousPasswordsAsync(ApplicationUser user, string password)
        {
            user.PreviousUserPasswords.Add(new PreviousPassword() { UserId = user.Id, Password = user.PasswordHash });

            await UpdateAsync(user).ConfigureAwait(false);
        }

    }
}
