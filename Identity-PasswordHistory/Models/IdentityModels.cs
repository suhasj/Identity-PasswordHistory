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

namespace Identity_PasswordHistory.Models
{
    // You can add profile data for the user by adding more properties to your ApplicationUser class, please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationUser : IdentityUser
    {
        public ApplicationUser()
            : base()
        {
            _PasswordHistory = new PasswordQueue<string>(2);
        }
        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }

        [NotMapped]
        public PasswordQueue<string> _PasswordHistory { get; set; }

        public string PasswordHistory
        {
            get
            {
                return String.Join(":", _PasswordHistory.ToArray());
            }
            set
            {
                _PasswordHistory = new PasswordQueue<string>(value.Split(':'), 2);
            }
        }
    }
    public class PasswordQueue<T> : Queue<T>
    {
        public int Limit { get; set; }
        public PasswordQueue(int limit)
            : base(limit)
        {
            Limit = limit;
        }

        public PasswordQueue(IEnumerable<T> collection, int limit)
            : base(collection)
        {
            Limit = limit;
        }

        public new void Enqueue(T item)
        {
            if (this.Count >= this.Limit)
            {
                this.Dequeue();
            }
            base.Enqueue(item);
        }
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
            var user = await FindByIdAsync(userId);

            if (user._PasswordHistory.ToArray().Where(x => PasswordHasher.VerifyHashedPassword(x, newPassword) == PasswordVerificationResult.Success).Count() > 0)
            {
                return await Task.FromResult(IdentityResult.Failed("Cannot reuse old password"));
            }
            else
            {
                var store = Store as ApplicationUserStore;
                await store.AddToPasswordHistoryAsync(user, PasswordHasher.HashPassword(newPassword));
            }

            return await base.ChangePasswordAsync(userId, currentPassword, newPassword);
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

            await AddToPasswordHistoryAsync(user, user.PasswordHash);
        }

        public async Task AddToPasswordHistoryAsync(ApplicationUser user, string password)
        {
            user._PasswordHistory.Enqueue(password);

            await UpdateAsync(user).ConfigureAwait(false);
        }

    }
}
