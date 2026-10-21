package com.authentication.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.authentication.config.security.SessionAuthentication;
import com.authentication.models.Role;
import com.authentication.models.RoleNames;
import com.authentication.models.UserAuth;
import com.authentication.models.request.UserCreatePayload;
import com.authentication.models.request.UserRegisPayload;
import com.authentication.models.request.UserUpdatePayload;
import com.authentication.repository.UserAuthRepository;

@ExtendWith(MockitoExtension.class)
class UserManagementServiceTest {

    @Mock UserAuthRepository repository;
    @Mock UserRegisService registrationService;
    @Mock PasswordEncoder encoder;
    @Mock RoleService roleService;
    @InjectMocks UserManagementService service;

    @BeforeEach
    void rolesResolveFromTheRoleTable() {
        lenient().when(roleService.require(any())).thenAnswer(inv -> new Role(inv.getArgument(0)));
    }

    private static UserAuth account(String roleName, boolean enabled) {
        return UserAuth.builder()
                .id(UUID.randomUUID())
                .email(UUID.randomUUID() + "@bank.com")
                .password("hash")
                .customerId(UUID.randomUUID())
                .role(new Role(roleName))
                .enabled(enabled)
                .build();
    }

    private static Authentication actorOf(UserAuth user) {
        return SessionAuthentication.from(user);
    }

    private static void assertRejected(ThrowingCallable call, HttpStatus status) {
        assertThatThrownBy(call).isInstanceOfSatisfying(UserManagementException.class,
                e -> assertThat(e.getStatus()).isEqualTo(status));
    }

    @Test
    void adminListsEveryAccount() {
        when(repository.findAll(any(Pageable.class))).thenReturn(new PageImpl<>(List.of(account(RoleNames.ADMIN, true))));

        var page = service.list(actorOf(account(RoleNames.ADMIN, true)), 0, 20);

        assertThat(page.content()).hasSize(1);
        verify(repository, never()).findByRole_NameNot(any(), any());
    }

    @Test
    void managerListExcludesAdminAccounts() {
        when(repository.findByRole_NameNot(eq(RoleNames.ADMIN), any(Pageable.class))).thenReturn(Page.empty());

        service.list(actorOf(account(RoleNames.MANAGER, true)), 0, 20);

        verify(repository, never()).findAll(any(Pageable.class));
        verify(repository).findByRole_NameNot(eq(RoleNames.ADMIN), any(Pageable.class));
    }

    @Test
    void listClampsPageSizeAndPage() {
        when(repository.findAll(any(Pageable.class))).thenReturn(Page.empty());
        var admin = actorOf(account(RoleNames.ADMIN, true));
        ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);

        service.list(admin, -3, 500);
        verify(repository).findAll(pageable.capture());
        assertThat(pageable.getValue().getPageNumber()).isZero();
        assertThat(pageable.getValue().getPageSize()).isEqualTo(UserManagementService.MAX_PAGE_SIZE);

        service.list(admin, 0, 0);
        verify(repository, org.mockito.Mockito.times(2)).findAll(pageable.capture());
        assertThat(pageable.getValue().getPageSize()).isEqualTo(1);
    }

    @Test
    void managerCannotViewAdminAccount() {
        var admin = account(RoleNames.ADMIN, true);
        when(repository.findById(admin.getId())).thenReturn(Optional.of(admin));

        assertRejected(() -> service.get(actorOf(account(RoleNames.MANAGER, true)), admin.getId()), HttpStatus.FORBIDDEN);
    }

    @Test
    void managerCannotUpdateOrDeleteAdminAccount() {
        var admin = account(RoleNames.ADMIN, true);
        when(repository.findById(admin.getId())).thenReturn(Optional.of(admin));
        var manager = actorOf(account(RoleNames.MANAGER, true));

        assertRejected(() -> service.update(manager, admin.getId(),
                UserUpdatePayload.builder().enabled(false).build()), HttpStatus.FORBIDDEN);
        assertRejected(() -> service.delete(manager, admin.getId()), HttpStatus.FORBIDDEN);

        verify(repository, never()).save(any());
        verify(repository, never()).delete(any());
    }

    @Test
    void managerCannotCreateOrAssignAdminRole() {
        var manager = actorOf(account(RoleNames.MANAGER, true));
        var payload = UserCreatePayload.builder()
                .customerId(UUID.randomUUID()).email("new@bank.com").password("longenough").role(RoleNames.ADMIN).build();

        assertRejected(() -> service.create(manager, payload), HttpStatus.FORBIDDEN);

        verifyNoInteractions(registrationService);
    }

    @Test
    void managerCannotPromoteUserToAdmin() {
        var target = account(RoleNames.CUSTOMER, true);
        when(repository.findById(target.getId())).thenReturn(Optional.of(target));
        var manager = actorOf(account(RoleNames.MANAGER, true));

        assertRejected(() -> service.update(manager, target.getId(),
                UserUpdatePayload.builder().role(RoleNames.ADMIN).build()), HttpStatus.FORBIDDEN);
        verify(repository, never()).save(any());
    }

    @Test
    void createDefaultsRoleToCustomerAndReusesCustomerValidation() {
        UUID customerId = UUID.randomUUID();
        var saved = account(RoleNames.CUSTOMER, true);
        when(registrationService.createLogin(any(UserRegisPayload.class), eq(new Role(RoleNames.CUSTOMER)))).thenReturn(saved);

        var created = service.create(actorOf(account(RoleNames.MANAGER, true)), UserCreatePayload.builder()
                .customerId(customerId).email("new@bank.com").password("longenough").build());

        ArgumentCaptor<UserRegisPayload> registration = ArgumentCaptor.forClass(UserRegisPayload.class);
        verify(registrationService).createLogin(registration.capture(), eq(new Role(RoleNames.CUSTOMER)));
        assertThat(registration.getValue().getCustomerId()).isEqualTo(customerId);
        assertThat(registration.getValue().getEmail()).isEqualTo("new@bank.com");
        assertThat(created.email()).isEqualTo(saved.getEmail());
    }

    @Test
    void createTurnsRegistrationFailureIntoBadRequest() {
        when(registrationService.createLogin(any(), any()))
                .thenThrow(new RuntimeException("User already exists with email: new@bank.com"));

        assertRejected(() -> service.create(actorOf(account(RoleNames.ADMIN, true)), UserCreatePayload.builder()
                .customerId(UUID.randomUUID()).email("new@bank.com").password("longenough").build()),
                HttpStatus.BAD_REQUEST);
    }

    @Test
    void getReturnsNotFoundForUnknownId() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.empty());

        assertRejected(() -> service.get(actorOf(account(RoleNames.ADMIN, true)), id), HttpStatus.NOT_FOUND);
    }

    @Test
    void updateChangesEmailPasswordRoleAndEnabledAndEncodesPassword() {
        var target = account(RoleNames.MANAGER, true);
        when(repository.findById(target.getId())).thenReturn(Optional.of(target));
        when(repository.findByEmail("moved@bank.com")).thenReturn(Optional.empty());
        when(encoder.encode("newpassword")).thenReturn("new-hash");
        when(repository.save(any(UserAuth.class))).thenAnswer(inv -> inv.getArgument(0));

        var response = service.update(actorOf(account(RoleNames.ADMIN, true)), target.getId(), UserUpdatePayload.builder()
                .email("moved@bank.com").password("newpassword").role(RoleNames.CUSTOMER).enabled(false).build());

        assertThat(target.getEmail()).isEqualTo("moved@bank.com");
        assertThat(target.getPassword()).isEqualTo("new-hash");
        assertThat(target.getRoleName()).isEqualTo(RoleNames.CUSTOMER);
        assertThat(target.isEnabled()).isFalse();
        assertThat(response.role()).isEqualTo(RoleNames.CUSTOMER);
    }

    @Test
    void updateRejectsEmailAlreadyInUse() {
        var target = account(RoleNames.CUSTOMER, true);
        when(repository.findById(target.getId())).thenReturn(Optional.of(target));
        when(repository.findByEmail("taken@bank.com")).thenReturn(Optional.of(account(RoleNames.CUSTOMER, true)));

        assertRejected(() -> service.update(actorOf(account(RoleNames.ADMIN, true)), target.getId(),
                UserUpdatePayload.builder().email("taken@bank.com").build()), HttpStatus.BAD_REQUEST);
        verify(repository, never()).save(any());
    }

    @Test
    void updateRejectsBlankEmail() {
        var target = account(RoleNames.CUSTOMER, true);
        when(repository.findById(target.getId())).thenReturn(Optional.of(target));

        assertRejected(() -> service.update(actorOf(account(RoleNames.ADMIN, true)), target.getId(),
                UserUpdatePayload.builder().email("   ").build()), HttpStatus.BAD_REQUEST);
    }

    @Test
    void nullFieldsLeaveAccountUnchanged() {
        var target = account(RoleNames.CUSTOMER, true);
        when(repository.findById(target.getId())).thenReturn(Optional.of(target));
        when(repository.save(any(UserAuth.class))).thenAnswer(inv -> inv.getArgument(0));

        service.update(actorOf(account(RoleNames.ADMIN, true)), target.getId(), UserUpdatePayload.builder().build());

        assertThat(target.getRoleName()).isEqualTo(RoleNames.CUSTOMER);
        assertThat(target.isEnabled()).isTrue();
        verifyNoInteractions(encoder);
    }

    @Test
    void selfRoleChangeIsRejected() {
        var admin = account(RoleNames.ADMIN, true);
        when(repository.findById(admin.getId())).thenReturn(Optional.of(admin));

        assertRejected(() -> service.update(actorOf(admin), admin.getId(),
                UserUpdatePayload.builder().role(RoleNames.CUSTOMER).build()), HttpStatus.BAD_REQUEST);
    }

    @Test
    void selfDisableIsRejectedEvenAfterEmailChange() {
        var manager = account(RoleNames.MANAGER, true);
        when(repository.findById(manager.getId())).thenReturn(Optional.of(manager));
        // The session still carries the old email, so self-identification must rely on customerId.
        Authentication stale = SessionAuthentication.from(UserAuth.builder()
                .email("old@bank.com").password("x").customerId(manager.getCustomerId()).role(new Role(RoleNames.MANAGER)).build());

        assertRejected(() -> service.update(stale, manager.getId(),
                UserUpdatePayload.builder().enabled(false).build()), HttpStatus.BAD_REQUEST);
    }

    @Test
    void lastActiveAdminCannotBeDemotedOrDisabled() {
        var otherAdmin = account(RoleNames.ADMIN, true);
        when(repository.findById(otherAdmin.getId())).thenReturn(Optional.of(otherAdmin));
        when(repository.countByRole_NameAndEnabled(RoleNames.ADMIN, true)).thenReturn(1L);
        var actor = actorOf(account(RoleNames.ADMIN, true));

        assertRejected(() -> service.update(actor, otherAdmin.getId(),
                UserUpdatePayload.builder().role(RoleNames.MANAGER).build()), HttpStatus.BAD_REQUEST);
        assertRejected(() -> service.update(actor, otherAdmin.getId(),
                UserUpdatePayload.builder().enabled(false).build()), HttpStatus.BAD_REQUEST);
        verify(repository, never()).save(any());
    }

    @Test
    void selfDeleteIsRejected() {
        var admin = account(RoleNames.ADMIN, true);
        when(repository.findById(admin.getId())).thenReturn(Optional.of(admin));

        assertRejected(() -> service.delete(actorOf(admin), admin.getId()), HttpStatus.BAD_REQUEST);
        verify(repository, never()).delete(any());
    }

    @Test
    void lastActiveAdminCannotBeDeleted() {
        var otherAdmin = account(RoleNames.ADMIN, true);
        when(repository.findById(otherAdmin.getId())).thenReturn(Optional.of(otherAdmin));
        when(repository.countByRole_NameAndEnabled(RoleNames.ADMIN, true)).thenReturn(1L);

        assertRejected(() -> service.delete(actorOf(account(RoleNames.ADMIN, true)), otherAdmin.getId()),
                HttpStatus.BAD_REQUEST);
        verify(repository, never()).delete(any());
    }

    @Test
    void disabledAdminCanBeDeletedWithoutActiveAdminCheck() {
        var disabledAdmin = account(RoleNames.ADMIN, false);
        when(repository.findById(disabledAdmin.getId())).thenReturn(Optional.of(disabledAdmin));

        service.delete(actorOf(account(RoleNames.ADMIN, true)), disabledAdmin.getId());

        verify(repository).delete(disabledAdmin);
        verify(repository, never()).countByRole_NameAndEnabled(anyString(), anyBoolean());
    }

    @Test
    void managerCanDeleteUserAccount() {
        var target = account(RoleNames.CUSTOMER, true);
        when(repository.findById(target.getId())).thenReturn(Optional.of(target));

        service.delete(actorOf(account(RoleNames.MANAGER, true)), target.getId());

        verify(repository).delete(target);
    }
}
