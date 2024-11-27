package netology.dao_hibernate.repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;
import netology.dao_hibernate.entity.Person;
import netology.dao_hibernate.entity.PersonID;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataEntity implements CommandLineRunner {
    @PersistenceContext
    EntityManager entityManager;
    @Override
    @Transactional
    public void run(String... args) throws Exception {

        Person vadim = Person.builder().contact(PersonID.builder()
                        .name("Vadim")
                        .surname("Volkov")
                        .age(33)
                        .build())
                .phoneNumber("89528880088")
                .cityOfLiving("Tomsk")
                .build();

        Person danila = Person.builder().contact(PersonID.builder()
                        .name("Danila")
                        .surname("Volkov")
                        .age(3)
                        .build())
                .phoneNumber("89527770077")
                .cityOfLiving("Tomsk")
                .build();

        Person olga = Person.builder().contact(PersonID.builder()
                        .name("Olga")
                        .surname("Volkova")
                        .age(32)
                        .build())
                .phoneNumber("89131181808")
                .cityOfLiving("Moscow")
                .build();

    }
}