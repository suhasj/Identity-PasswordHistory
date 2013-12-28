using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Identity_PasswordHistory.Startup))]
namespace Identity_PasswordHistory
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
