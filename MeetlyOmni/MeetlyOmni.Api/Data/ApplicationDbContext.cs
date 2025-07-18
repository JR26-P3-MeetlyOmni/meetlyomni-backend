using MeetlyOmni.Api.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace MeetlyOmni.Api.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<Member> Members { get; set; }
        public DbSet<Organization> Organizations { get; set; }
        public DbSet<RaffleTicket> RaffleTickets { get; set; }
        public DbSet<MemberActivityLog> MemberActivityLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);

            base.OnModelCreating(modelBuilder);
        }
    }
}
