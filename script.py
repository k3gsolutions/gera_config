import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import sessionmaker
from datetime import datetime

#Configurando a engine do BD
engine = create_engine('sqlite:///tenant_groups.db')
engine = create_engine('sqlite:///NetboxTenant.db')
# engine = create_engine('sqlite:///devices.db')
# engine = create_engine('sqlite:///dcim_devicetypes.db')
#Configurando a sessão do BD
Session = sessionmaker(bind=engine)


#criando tabela
Base = declarative_base()

class TenantGroup(Base):
    __tablename__ = 'tenant_groups'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    slug = Column(String)
    description = Column(String)

class NetboxTenant(Base):
    __tablename__ = 'netbox_tenants'
    id = Column(Integer, primary_key=True)
    netbox_id = Column(Integer, unique=True)  # ID do Netbox
    name = Column(String, nullable=False)
    slug = Column(String)
    description = Column(String)
    last_updated = Column(String)  # Para controle de atualização

def sync_tenants_to_db(tenants_data):
    session = Session()
    try:
        for tenant in tenants_data:
            # Verifica se o tenant já existe
            existing = session.query(NetboxTenant).filter_by(netbox_id=tenant['id']).first()
            
            if existing:
                # Atualiza os dados existentes
                existing.name = tenant['name']
                existing.slug = tenant.get('slug', '')
                existing.description = tenant.get('description', '')
                existing.last_updated = datetime.now().isoformat()
            else:
                # Cria novo registro
                new_tenant = NetboxTenant(
                    netbox_id=tenant['id'],
                    name=tenant['name'],
                    slug=tenant.get('slug', ''),
                    description=tenant.get('description', ''),
                    last_updated=datetime.now().isoformat()
                )
                session.add(new_tenant)
        
        session.commit()
        print("Tenants sincronizados com sucesso!")
    except Exception as e:
        session.rollback()
        print(f"Erro ao sincronizar tenants: {str(e)}")
    finally:
        session.close()

class Device(Base):
    __tablename__ = 'devices'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    device_type_id = Column(Integer)
    device_role_id = Column(Integer)
    platform_id = Column(Integer)
    site_id = Column(Integer)
    tenant_id = Column(Integer)
    status = Column(Integer)
    serial = Column(String)
    asset_tag = Column(String)

class DeviceType(Base):
    __tablename__ = 'dcim_devicetypes'
    id = Column(Integer, primary_key=True)
    model = Column(String, nullable=False)
    manufacturer_id = Column(Integer)
    slug = Column(String)
    u_height = Column(Integer)

def insert_tenant_group(name, slug, description):
    session = Session()
    try:
        if all([name]):
            tenant_group = TenantGroup(name=name, slug=slug, description=description)
            session.add(tenant_group)
            session.commit()
            print(f"Grupo de inquilinos '{name}' inserido com sucesso!")
        else:
            print("Erro: Todos os campos são obrigatórios.")
    except Exception as e:
        session.rollback()
        print(f"Erro ao inserir o grupo de inquilinos: {str(e)}")
    finally:
        session.close()

    session.add(tenant_group)
    session.commit()

def select_tenant_group(tenant_group=''):
    session = Session()
    try:
        if tenant_group:
            dados = session.query(TenantGroup).filter(TenantGroup.name == tenant_group)
            print("Grupos de inquilinos:")
        else:
            dados = session.query(TenantGroup).all()
            print("Grupos de inquilinos:")
        for i in dados:
            print(f"ID: {i.id}, Nome: {i.name}, Slug: {i.slug}, Descrição: {i.description}")
    except Exception as e:
            print(f"Erro ao selecionar os grupos de inquilinos: {str(e)}")
    finally:
            session.close()



if __name__ == '__main__':
    os.system('clear')
    Base.metadata.create_all(engine)
#    insert_tenant_group('teste', 'teste', 'teste')
    select_tenant_group()