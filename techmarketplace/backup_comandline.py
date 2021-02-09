import sys
import click


@click.command()
@click.option('--database',nargs=1,type=str,help='Backup database')
def database_backup(n):
    click.echo('%s',n)


if __name__ == "__main__":
    database_backup()